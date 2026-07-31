import StageA.RelationalInterpreterX87ReplayBridgeRuntime
import StageA.RelationalInterpreterKernelMixedReplayWorld
import StageA.RelationalInterpreterX87ReplayMemoryFrame

namespace StageA.Relational.InterpreterKernelX87Execution

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelMixedReplay
open StageA.Relational.InterpreterKernelMixedReplayWorld
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.Relational.InterpreterX87ReplayBridgeRuntime
open StageA.Relational.InterpreterX87ReplayMemoryFrame

/-! # Exact x87 replay-kernel execution

The fixed-template certificate below cannot submit paths, handler semantics, or
an already-related x87 output.  It supplies exact `runRelatedSteps` equations,
successful original/candidate singleton executions, frame preservation, and an
encoded candidate output.  `executeKernelReduction` derives handler equality
and the replay-address `X87.StateRelated` result using the reviewed semantic
executor. -/

structure ExactNativeX87ReplayKernelProgramBinding
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram) : Prop where
  peExact : program.pe = pe
  importsExact : program.imports = imports
  imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32
  targetInventory : program.indirectTargets.targetSet?
    table.callInstruction.rva .call = some table.nativeTargetSet

/-! ## Opaque exact-step handles

`CheckedKernelMixedReplayInstruction` already proves that the instruction was
decoded from the exact PE bytes and that its reviewed semantic handler exists.
The constructors below expose the corresponding decoder result once.  Bridge
composition can then use these opaque equalities without re-running PE fetch,
decode, and static symbolic interpretation for every source state. -/

inductive ExactKernelMixedReplayStaticStep
    (pe : PE32) (imports : List PEImport) where
  | ordinary
      (entry : CheckedKernelMixedReplayInstruction pe imports)
      (instruction : KernelInstruction)
      (instructionExact : entry.instruction = .ordinary instruction)
      (specializedDecodersClear :
        KernelMixedReplayInstruction.specializedDecodersClear pe instruction =
          true)
      (decoded : DecodedInstruction)
      (decodedExact : instruction.decode? pe = some decoded)
  | x87Frame
      (entry : CheckedKernelMixedReplayInstruction pe imports)
      (instruction : KernelX87FrameInstruction)
      (instructionExact : entry.instruction = .x87Frame instruction)
      (decoded : KernelX87FrameDecoded)
      (decodedExact : instruction.decode? pe = some decoded)
  | x87Command
      (entry : CheckedKernelMixedReplayInstruction pe imports)
      (instruction : KernelX87CommandInstruction)
      (instructionExact : entry.instruction = .x87Command instruction)
      (frameDecoderClear :
        KernelMixedReplayInstruction.frameDecoderClear pe instruction = true)
      (decoded : StageA.Relational.X87.DecodedCommand)
      (decodedExact : instruction.decode? pe = some decoded)

def ExactKernelMixedReplayStaticStep.instruction :
    ExactKernelMixedReplayStaticStep pe imports ->
      KernelMixedReplayInstruction
  | .ordinary _ instruction _ _ _ _ => .ordinary instruction
  | .x87Frame _ instruction _ _ _ => .x87Frame instruction
  | .x87Command _ instruction _ _ _ _ => .x87Command instruction

def ExactKernelMixedReplayStaticStep.entry :
    ExactKernelMixedReplayStaticStep pe imports ->
      CheckedKernelMixedReplayInstruction pe imports
  | .ordinary entry _ _ _ _ _ => entry
  | .x87Frame entry _ _ _ _ => entry
  | .x87Command entry _ _ _ _ _ => entry

@[simp] theorem ExactKernelMixedReplayStaticStep.instruction_exact
    (step : ExactKernelMixedReplayStaticStep pe imports) :
    step.instruction = step.entry.instruction := by
  cases step with
  | ordinary _ _ instructionExact _ _ _ =>
      exact instructionExact.symm
  | x87Frame _ _ instructionExact _ _ =>
      exact instructionExact.symm
  | x87Command _ _ instructionExact _ _ _ =>
      exact instructionExact.symm

/-- Extract the exact static decoder result from a checked mixed instruction.
This construction is total because each mixed checker is definitionally the
corresponding decoder/semantic `isSome` check. -/
def exactKernelMixedReplayStaticStep
    (entry : CheckedKernelMixedReplayInstruction pe imports) :
    ExactKernelMixedReplayStaticStep pe imports := by
  rcases entry with ⟨mixedInstruction, checked⟩
  cases mixedInstruction with
  | ordinary instruction =>
      let originalEntry : CheckedKernelMixedReplayInstruction pe imports :=
        ⟨.ordinary instruction, checked⟩
      have checkedParts := checked
      simp only [KernelMixedReplayInstruction.checked, Bool.and_eq_true] at checkedParts
      rcases checkedParts with ⟨ordinaryChecked, specializedDecodersClear⟩
      unfold KernelInstruction.checked at ordinaryChecked
      cases decodedExact : instruction.decode? pe with
      | none =>
          simp [KernelInstruction.semantics?, decodedExact] at ordinaryChecked
      | some decoded =>
          exact .ordinary originalEntry
            instruction rfl
            specializedDecodersClear decoded decodedExact
  | x87Frame instruction =>
      let originalEntry : CheckedKernelMixedReplayInstruction pe imports :=
        ⟨.x87Frame instruction, checked⟩
      have frameChecked := checked
      simp only [KernelMixedReplayInstruction.checked] at frameChecked
      unfold KernelX87FrameInstruction.checked at frameChecked
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at frameChecked
      | some decoded =>
          exact .x87Frame originalEntry
            instruction rfl decoded decodedExact
  | x87Command instruction =>
      let originalEntry : CheckedKernelMixedReplayInstruction pe imports :=
        ⟨.x87Command instruction, checked⟩
      have checkedParts := checked
      simp only [KernelMixedReplayInstruction.checked, Bool.and_eq_true] at checkedParts
      rcases checkedParts with ⟨commandChecked, frameDecoderClear⟩
      unfold KernelX87CommandInstruction.checked at commandChecked
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at commandChecked
      | some decoded =>
          exact .x87Command originalEntry
            instruction rfl frameDecoderClear decoded decodedExact

def exactKernelMixedReplayStaticSteps
    (entries : List (CheckedKernelMixedReplayInstruction pe imports)) :
    List (ExactKernelMixedReplayStaticStep pe imports) :=
  entries.map exactKernelMixedReplayStaticStep

inductive NativeX87ReplayDecodedStep where
  | ordinary (rva : Nat) (decoded : DecodedInstruction)
  | x87Frame (rva : Nat) (decoded : KernelX87FrameDecoded)
  | x87Command (rva : Nat) (decoded : StageA.Relational.X87.DecodedCommand)
deriving Repr, DecidableEq

inductive NativeX87ReplayTemplateRole where
  | ordinary (rva : Nat) (instruction : Instruction) (size : Nat)
  | x87Frame (rva : Nat) (decoded : KernelX87FrameDecoded)
  | x87Command (rva : Nat) (decoded : StageA.Relational.X87.DecodedCommand)
deriving Repr, DecidableEq

def NativeX87ReplayTemplateRole.rva : NativeX87ReplayTemplateRole -> Nat
  | .ordinary rva _ _ | .x87Frame rva _ | .x87Command rva _ => rva

def NativeX87ReplayDecodedStep.role : NativeX87ReplayDecodedStep ->
    NativeX87ReplayTemplateRole
  | .ordinary rva decoded => .ordinary rva decoded.instruction decoded.size
  | .x87Frame rva decoded => .x87Frame rva decoded
  | .x87Command rva decoded => .x87Command rva decoded

def ExactKernelMixedReplayStaticStep.decoded :
    ExactKernelMixedReplayStaticStep pe imports -> NativeX87ReplayDecodedStep
  | .ordinary _ instruction _ _ decoded _ =>
      .ordinary instruction.rva decoded
  | .x87Frame _ instruction _ decoded _ =>
      .x87Frame instruction.rva decoded
  | .x87Command _ instruction _ _ decoded _ =>
      .x87Command instruction.rva decoded

def exactKernelMixedReplayTemplateRoles
    (entries : List (CheckedKernelMixedReplayInstruction pe imports)) :
    List NativeX87ReplayTemplateRole :=
  (exactKernelMixedReplayStaticSteps entries).map (·.decoded.role)

def kernelMixedReplayTemplateRole?
    (pe : PE32) (entry : CheckedKernelMixedReplayInstruction pe imports) :
    Option NativeX87ReplayTemplateRole :=
  match entry.instruction with
  | .ordinary instruction => do
      let decoded <- instruction.decode? pe
      some (.ordinary instruction.rva decoded.instruction decoded.size)
  | .x87Frame instruction => do
      let decoded <- instruction.decode? pe
      some (.x87Frame instruction.rva decoded)
  | .x87Command instruction => do
      let decoded <- instruction.decode? pe
      some (.x87Command instruction.rva decoded)

def kernelMixedReplayTemplateRoles?
    (pe : PE32) (entries : List (CheckedKernelMixedReplayInstruction pe imports)) :
    Option (List NativeX87ReplayTemplateRole) :=
  entries.mapM (kernelMixedReplayTemplateRole? pe)

private theorem kernelMixedReplayTemplateRole?_rva
    (entry : CheckedKernelMixedReplayInstruction pe imports)
    (role : NativeX87ReplayTemplateRole)
    (exact : kernelMixedReplayTemplateRole? pe entry = some role) :
    entry.instruction.rva = role.rva := by
  rcases entry with ⟨instruction, checked⟩
  cases instruction with
  | ordinary instruction =>
      unfold kernelMixedReplayTemplateRole? at exact
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at exact
      | some decoded =>
          simp [decodedExact] at exact
          subst role
          rfl
  | x87Frame instruction =>
      unfold kernelMixedReplayTemplateRole? at exact
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at exact
      | some decoded =>
          simp [decodedExact] at exact
          subst role
          rfl
  | x87Command instruction =>
      unfold kernelMixedReplayTemplateRole? at exact
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at exact
      | some decoded =>
          simp [decodedExact] at exact
          subst role
          rfl

private theorem kernelMixedReplayTemplateRoles?_length
    (entries : List (CheckedKernelMixedReplayInstruction pe imports))
    (roles : List NativeX87ReplayTemplateRole)
    (exact : kernelMixedReplayTemplateRoles? pe entries = some roles) :
    entries.length = roles.length := by
  induction entries generalizing roles with
  | nil =>
      simp [kernelMixedReplayTemplateRoles?] at exact
      subst roles
      rfl
  | cons entry tail induction =>
      unfold kernelMixedReplayTemplateRoles? at exact
      cases headExact : kernelMixedReplayTemplateRole? pe entry with
      | none => simp [headExact] at exact
      | some head =>
          cases tailExact :
              List.mapM (kernelMixedReplayTemplateRole? pe) tail with
          | none => simp [headExact, tailExact] at exact
          | some rest =>
              simp [headExact, tailExact] at exact
              subst roles
              simp only [List.length_cons, Nat.succ.injEq]
              apply induction rest
              simpa [kernelMixedReplayTemplateRoles?] using tailExact

private theorem kernelMixedReplayTemplateRoles?_head_rva
    (entry : CheckedKernelMixedReplayInstruction pe imports)
    (tail : List (CheckedKernelMixedReplayInstruction pe imports))
    (role : NativeX87ReplayTemplateRole)
    (roles : List NativeX87ReplayTemplateRole)
    (exact :
      kernelMixedReplayTemplateRoles? pe (entry :: tail) =
        some (role :: roles)) :
    entry.instruction.rva = role.rva := by
  unfold kernelMixedReplayTemplateRoles? at exact
  cases headExact : kernelMixedReplayTemplateRole? pe entry with
  | none => simp [headExact] at exact
  | some head =>
      cases tailExact :
          List.mapM (kernelMixedReplayTemplateRole? pe) tail with
      | none => simp [headExact, tailExact] at exact
      | some rest =>
          simp [headExact, tailExact] at exact
          have headRva :=
            kernelMixedReplayTemplateRole?_rva entry head headExact
          simpa [exact.1] using headRva

def nativeX87ReplayFixedTemplateInstructionRegionSize : Nat :=
  nativeX87ReplayBridgeCaptureOffset - nativeX87ReplayBridgeInstructionOffset

private def nativeX87ReplayAddressing
    (base : Option Reg) (displacement : Nat) : Addressing := {
  base
  index := none
  scaleShift := 0
  displacement
}

private def nativeX87ReplayMemory
    (base : Option Reg) (displacement : Nat) : Operand32 :=
  .memory (nativeX87ReplayAddressing base displacement)

@[simp] private theorem wordOfNat_mod_wordSize (value : Nat) :
    BitVec.ofNat 32 (value % (2 ^ 32)) = BitVec.ofNat 32 value := by
  apply BitVec.eq_of_toNat_eq
  simp [BitVec.toNat_ofNat, Nat.mod_mod]

@[simp] private theorem nativeX87ReplayAddressing_none_eval
    (displacement : Nat) (input : MachineState) :
    ((nativeX87ReplayAddressing none displacement).expression
        initialSymbolic.registers).eval input =
      BitVec.ofNat 32 displacement := by
  cases displacement <;>
    simp [nativeX87ReplayAddressing, Addressing.expression, initialSymbolic,
      Expr.addNormalized, StageA.Formal.Expr.eval]

@[simp] private theorem nativeX87ReplayAddressing_some_eval
    (register : Reg) (displacement : Nat) (input : MachineState) :
    ((nativeX87ReplayAddressing (some register) displacement).expression
        initialSymbolic.registers).eval input =
      input.registers.get register + BitVec.ofNat 32 displacement := by
  cases register <;> cases displacement <;>
    simp [nativeX87ReplayAddressing, Addressing.expression, initialSymbolic,
      Registers.get, Expr.addNormalized, StageA.Formal.Expr.eval]

private theorem readNativeX87ReplayMemoryNone
    (displacement : Nat) (input : MachineState) :
    (readOperand32 initialSymbolic
        (nativeX87ReplayMemory none displacement)).eval input =
      Memory.read32 input.memory (BitVec.ofNat 32 displacement) := by
  rw [readOperand32_initialSymbolic_eval]
  simp [nativeX87ReplayMemory, evalOperand32, evalAddressing]

private theorem readNativeX87ReplayMemorySome
    (register : Reg) (displacement : Nat) (input : MachineState) :
    (readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some register) displacement)).eval input =
      Memory.read32 input.memory
        (input.registers.get register + BitVec.ofNat 32 displacement) := by
  rw [readOperand32_initialSymbolic_eval]
  simp [nativeX87ReplayMemory, evalOperand32, evalAddressing]

private theorem readNativeX87ReplayMemorySome_eq
    (register : Reg) (displacement : Nat) (input : MachineState)
    (base value : Word)
    (baseExact : input.registers.get register = base)
    (valueExact :
      Memory.read32 input.memory
        (base + BitVec.ofNat 32 displacement) = value) :
    (readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some register) displacement)).eval input =
      value := by
  rw [readNativeX87ReplayMemorySome, baseExact]
  exact valueExact

private def nativeX87ReplayByteMemory
    (base : Option Reg) (displacement : Nat) : Operand8 :=
  .memory (nativeX87ReplayAddressing base displacement)

private def nativeX87ReplayOrdinaryRole
    (baseRva offset : Nat) (instruction : Instruction) (size : Nat) :
    NativeX87ReplayTemplateRole :=
  .ordinary (baseRva + offset) instruction size

def nativeX87ReplayFixedTemplateEntryRoles
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    List NativeX87ReplayTemplateRole :=
  let base := mapping.bridgeTargetRva
  let active := (pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)
  [
    nativeX87ReplayOrdinaryRole base 0 (.pushReg .ebp) 1,
    nativeX87ReplayOrdinaryRole base 1 (.pushReg .ebx) 1,
    nativeX87ReplayOrdinaryRole base 2 (.pushReg .esi) 1,
    nativeX87ReplayOrdinaryRole base 3 (.pushReg .edi) 1,
    nativeX87ReplayOrdinaryRole base 4
      (.movFromOperand .eax (nativeX87ReplayMemory none active)) 5,
    nativeX87ReplayOrdinaryRole base 9
      (.movToOperand (nativeX87ReplayMemory (some .eax) 12) .esp) 3,
    .x87Frame (base + 12) {
      operation := .frStor
      addressing := nativeX87ReplayAddressing (some .eax) 20
      size := 3
    },
    nativeX87ReplayOrdinaryRole base 15
      (.movFromOperand .eax (nativeX87ReplayMemory (some .eax) 4)) 3,
    nativeX87ReplayOrdinaryRole base 18
      (.movFromOperand .ebx (nativeX87ReplayMemory (some .eax) 4)) 3,
    nativeX87ReplayOrdinaryRole base 21
      (.movFromOperand .ecx (nativeX87ReplayMemory (some .eax) 8)) 3,
    nativeX87ReplayOrdinaryRole base 24
      (.movFromOperand .esi (nativeX87ReplayMemory (some .eax) 16)) 3,
    nativeX87ReplayOrdinaryRole base 27
      (.movFromOperand .edi (nativeX87ReplayMemory (some .eax) 20)) 3,
    nativeX87ReplayOrdinaryRole base 30
      (.movFromOperand .ebp (nativeX87ReplayMemory (some .eax) 24)) 3,
    nativeX87ReplayOrdinaryRole base 33
      (.movFromOperand .esp (nativeX87ReplayMemory (some .eax) 28)) 3,
    nativeX87ReplayOrdinaryRole base 36
      (.pushOperand (nativeX87ReplayMemory (some .eax) 240)) 6,
    nativeX87ReplayOrdinaryRole base 42
      (.pushOperand (nativeX87ReplayMemory (some .eax) 0)) 2,
    nativeX87ReplayOrdinaryRole base 44
      (.movFromOperand .edx (nativeX87ReplayMemory (some .eax) 12)) 3,
    nativeX87ReplayOrdinaryRole base 47 (.popReg .eax) 1,
    nativeX87ReplayOrdinaryRole base 48 .popFlags 1,
    nativeX87ReplayOrdinaryRole base 49 .nop 1,
    nativeX87ReplayOrdinaryRole base 50 .nop 1,
    nativeX87ReplayOrdinaryRole base 51 .nop 1
  ]

private def nativeX87ReplayNopRoles :
    Nat -> Nat -> List NativeX87ReplayTemplateRole
  | _, 0 => []
  | rva, count + 1 =>
      .ordinary rva .nop 1 :: nativeX87ReplayNopRoles (rva + 1) count

def nativeX87ReplayFixedTemplateInstructionRoles
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (decoded : StageA.Relational.X87.DecodedCommand) :
    List NativeX87ReplayTemplateRole :=
  .x87Command mapping.instructionRva decoded ::
    nativeX87ReplayNopRoles
      (mapping.instructionRva + decoded.size)
      (nativeX87ReplayFixedTemplateInstructionRegionSize - decoded.size)

def nativeX87ReplayFixedTemplateCaptureRoles
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    List NativeX87ReplayTemplateRole :=
  let base := mapping.captureRva
  let active := (pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)
  [
    nativeX87ReplayOrdinaryRole base 0 .pushFlags 1,
    nativeX87ReplayOrdinaryRole base 1 (.pushReg .eax) 1,
    nativeX87ReplayOrdinaryRole base 2
      (.movFromOperand .eax (nativeX87ReplayMemory none active)) 5,
    .x87Frame (base + 7) {
      operation := .fnSave
      addressing := nativeX87ReplayAddressing (some .eax) 128
      size := 6
    },
    nativeX87ReplayOrdinaryRole base 13
      (.movFromOperand .edx (nativeX87ReplayMemory (some .eax) 8)) 3,
    nativeX87ReplayOrdinaryRole base 16
      (.movFromOperand .ecx (nativeX87ReplayMemory (some .esp) 0)) 3,
    nativeX87ReplayOrdinaryRole base 19
      (.movToOperand (nativeX87ReplayMemory (some .edx) 0) .ecx) 2,
    nativeX87ReplayOrdinaryRole base 21
      (.setCondition .below (nativeX87ReplayByteMemory (some .edx) 32)) 4,
    nativeX87ReplayOrdinaryRole base 25
      (.setCondition .parity (nativeX87ReplayByteMemory (some .edx) 48)) 4,
    nativeX87ReplayOrdinaryRole base 29
      (.setCondition .equal (nativeX87ReplayByteMemory (some .edx) 36)) 4,
    nativeX87ReplayOrdinaryRole base 33
      (.setCondition .sign (nativeX87ReplayByteMemory (some .edx) 40)) 4,
    nativeX87ReplayOrdinaryRole base 37
      (.setCondition .overflow (nativeX87ReplayByteMemory (some .edx) 44)) 4,
    nativeX87ReplayOrdinaryRole base 41
      (.movFromOperand .ebx (nativeX87ReplayMemory (some .esp) 4)) 4,
    nativeX87ReplayOrdinaryRole base 45
      (.movFromOperand .ecx (nativeX87ReplayMemory (some .eax) 4)) 3,
    nativeX87ReplayOrdinaryRole base 48
      (.movFromOperand .ecx (nativeX87ReplayMemory (some .ecx) 240)) 6,
    nativeX87ReplayOrdinaryRole base 54
      (.binary .and (.register .ecx) (.immediate 0xfffff32a)) 6,
    nativeX87ReplayOrdinaryRole base 60
      (.binary .and (.register .ebx) (.immediate 0x0cd5)) 6,
    nativeX87ReplayOrdinaryRole base 66
      (.binary .or (.register .ecx) (.register .ebx)) 2,
    nativeX87ReplayOrdinaryRole base 68
      (.movToOperand (nativeX87ReplayMemory (some .edx) 240) .ecx) 6
  ] ++ nativeX87ReplayNopRoles (base + 74) 10 ++ [
    nativeX87ReplayOrdinaryRole base 84
      (.movImmediate (nativeX87ReplayMemory (some .eax) 16) 0) 7,
    nativeX87ReplayOrdinaryRole base 91
      (.movFromOperand .esp (nativeX87ReplayMemory (some .eax) 12)) 3,
    nativeX87ReplayOrdinaryRole base 94 .clearDirection 1,
    nativeX87ReplayOrdinaryRole base 95 (.popReg .edi) 1,
    nativeX87ReplayOrdinaryRole base 96 (.popReg .esi) 1,
    nativeX87ReplayOrdinaryRole base 97 (.popReg .ebx) 1,
    nativeX87ReplayOrdinaryRole base 98 (.popReg .ebp) 1
  ]

def nativeX87ReplayFixedTemplateReturnRoles
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    List NativeX87ReplayTemplateRole :=
  [.ordinary mapping.returnRva .ret 1]

abbrev NativeX87ReplayFixedTemplateSemanticPlan :=
  StageA.Relational.X87.DecodedCommand

def NativeX87ReplayFixedTemplateSemanticPlan.command
    (plan : NativeX87ReplayFixedTemplateSemanticPlan) :
    StageA.Relational.X87.DecodedCommand :=
  plan

def nativeX87ReplayFixedTemplateSemanticPlan?
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (mapping : NativeX87ReplayBridgeFrameMapping)
    (mixedReplay : NativeX87ReplayFixedTemplateMixedReplay pe imports) :
    Option NativeX87ReplayFixedTemplateSemanticPlan := do
  let entry <- kernelMixedReplayTemplateRoles? pe mixedReplay.entry
  if entry != nativeX87ReplayFixedTemplateEntryRoles table pe mapping then none else
  let instruction <- kernelMixedReplayTemplateRoles? pe mixedReplay.instruction
  let command <- match instruction with
    | .x87Command rva decoded :: _ =>
        if rva == mapping.instructionRva then some decoded else none
    | _ => none
  if instruction !=
      nativeX87ReplayFixedTemplateInstructionRoles mapping command then none else
  let capture <- kernelMixedReplayTemplateRoles? pe mixedReplay.capture
  if capture != nativeX87ReplayFixedTemplateCaptureRoles table pe mapping then none else
  let returnPath <- kernelMixedReplayTemplateRoles? pe mixedReplay.returnPath
  if returnPath != nativeX87ReplayFixedTemplateReturnRoles mapping then none else
  some command

/-! ## Complete fixed-template static execution plan

The replay instruction occupies a variable-sized prefix of the fixed 20-byte
instruction region.  `instructionPathBytes` intentionally records only the
original x87 instruction, so it is not an execution span: the remaining bytes
are checked NOP padding that must execute before the capture cutpoint. -/

def nativeX87ReplayFixedTemplateInstructionRegion
    (mapping : NativeX87ReplayBridgeFrameMapping) : Bytes :=
  (mapping.bridgeBodyBytes.drop nativeX87ReplayBridgeInstructionOffset).take
    nativeX87ReplayFixedTemplateInstructionRegionSize

def nativeX87ReplayFixedTemplateExecutionSchedule?
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    Option NativeX87ReplayFixedTemplateSchedule := do
  let entryFuel <- decodeNativeX87ReplaySchedule?
    (mapping.bridgeBodyBytes.take nativeX87ReplayBridgeEntryScheduleSize)
  let instructionFuel <- decodeNativeX87ReplaySchedule?
    (nativeX87ReplayFixedTemplateInstructionRegion mapping)
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

def nativeX87ReplayFixedTemplateExecutionMixedReplay?
    (pe : PE32) (imports : List PEImport)
    (mapping : NativeX87ReplayBridgeFrameMapping) :
    Option (NativeX87ReplayFixedTemplateMixedReplay pe imports) := do
  let entry <- checkedKernelMixedReplaySpan? pe imports
    mapping.bridgeTargetRva nativeX87ReplayBridgeEntryScheduleSize
  let instruction <- checkedKernelMixedReplaySpan? pe imports
    mapping.instructionRva nativeX87ReplayFixedTemplateInstructionRegionSize
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

/-- Exact schedule and mixed decoder authority, separated from normalized shape
checking so generated modules compile each expensive fact once. -/
structure ExactNativeX87ReplayFixedTemplateStaticDecode
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) where
  schedule : NativeX87ReplayFixedTemplateSchedule
  mixedReplay : NativeX87ReplayFixedTemplateMixedReplay pe imports
  scheduleExact :
    nativeX87ReplayFixedTemplateExecutionSchedule?
        runtimeTarget.target.frameMapping =
      some schedule
  mixedReplayExact :
    nativeX87ReplayFixedTemplateExecutionMixedReplay? pe imports
        runtimeTarget.target.frameMapping =
      some mixedReplay

def exactNativeX87ReplayFixedTemplateStaticDecode?
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    Option (ExactNativeX87ReplayFixedTemplateStaticDecode runtimeTarget) := do
  match scheduleExact : nativeX87ReplayFixedTemplateExecutionSchedule?
      runtimeTarget.target.frameMapping with
  | none => none
  | some schedule =>
      match mixedReplayExact :
          nativeX87ReplayFixedTemplateExecutionMixedReplay? pe imports
            runtimeTarget.target.frameMapping with
      | none => none
      | some mixedReplay =>
          some {
            schedule
            mixedReplay
            scheduleExact
            mixedReplayExact
          }

def exactNativeX87ReplayFixedTemplateStaticDecodeOfIsSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (checked :
      (exactNativeX87ReplayFixedTemplateStaticDecode? runtimeTarget).isSome =
        true) :
    ExactNativeX87ReplayFixedTemplateStaticDecode runtimeTarget := by
  cases exact :
      exactNativeX87ReplayFixedTemplateStaticDecode? runtimeTarget with
  | none => simp [exact] at checked
  | some execution => exact execution

structure ExactNativeX87ReplayFixedTemplateSemanticPlan
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (staticDecode :
      ExactNativeX87ReplayFixedTemplateStaticDecode runtimeTarget) where
  plan : NativeX87ReplayFixedTemplateSemanticPlan
  exact :
    nativeX87ReplayFixedTemplateSemanticPlan? table pe
        runtimeTarget.target.frameMapping staticDecode.mixedReplay =
      some plan

def exactNativeX87ReplayFixedTemplateSemanticPlanOfIsSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (staticDecode :
      ExactNativeX87ReplayFixedTemplateStaticDecode runtimeTarget)
    (checked :
      (nativeX87ReplayFixedTemplateSemanticPlan? table pe
        runtimeTarget.target.frameMapping staticDecode.mixedReplay).isSome =
          true) :
    ExactNativeX87ReplayFixedTemplateSemanticPlan runtimeTarget staticDecode := by
  cases exact :
      nativeX87ReplayFixedTemplateSemanticPlan? table pe
        runtimeTarget.target.frameMapping staticDecode.mixedReplay with
  | none => simp [exact] at checked
  | some plan => exact ⟨plan, exact⟩

/-- Static authority for one target.  Every field is schedule, exact decoding,
or normalized source-independent template shape.  No machine state or execution
endpoint is submitted by generated code. -/
structure ExactNativeX87ReplayFixedTemplateStaticExecution
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    extends ExactNativeX87ReplayFixedTemplateStaticDecode runtimeTarget where
  semanticPlan : NativeX87ReplayFixedTemplateSemanticPlan
  semanticPlanExact :
    nativeX87ReplayFixedTemplateSemanticPlan? table pe
        runtimeTarget.target.frameMapping mixedReplay =
      some semanticPlan
  candidateDescriptor : StageA.Relational.X87.DecodedCommand
  candidateDescriptorExact :
    StageA.Relational.X87.decodeSingletonCommand pe
        (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
          runtimeTarget.addressMap.candidateInstructionRva).span =
      some candidateDescriptor
  semanticCommandExact : semanticPlan.command = candidateDescriptor
  entryFuelExact : schedule.entryFuel = mixedReplay.entry.length
  instructionFuelExact :
    schedule.instructionFuel = mixedReplay.instruction.length
  captureFuelExact : schedule.captureFuel = mixedReplay.capture.length
  returnFuelExact : schedule.returnFuel = mixedReplay.returnPath.length

def exactNativeX87ReplayFixedTemplateStaticExecution?
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    Option (ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget) := do
  let staticDecode <- exactNativeX87ReplayFixedTemplateStaticDecode? runtimeTarget
  match semanticPlanExact :
      nativeX87ReplayFixedTemplateSemanticPlan? table pe
        runtimeTarget.target.frameMapping staticDecode.mixedReplay with
  | none => none
  | some semanticPlan =>
      match candidateDescriptorExact :
          StageA.Relational.X87.decodeSingletonCommand pe
            (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
              runtimeTarget.addressMap.candidateInstructionRva).span with
      | none => none
      | some candidateDescriptor =>
          if semanticCommandExact :
              semanticPlan.command = candidateDescriptor then
            if fuelExact :
                staticDecode.schedule.entryFuel =
                    staticDecode.mixedReplay.entry.length ∧
                  staticDecode.schedule.instructionFuel =
                    staticDecode.mixedReplay.instruction.length ∧
                  staticDecode.schedule.captureFuel =
                    staticDecode.mixedReplay.capture.length ∧
                  staticDecode.schedule.returnFuel =
                    staticDecode.mixedReplay.returnPath.length then
              some {
                toExactNativeX87ReplayFixedTemplateStaticDecode := staticDecode
                semanticPlan
                semanticPlanExact
                candidateDescriptor
                candidateDescriptorExact
                semanticCommandExact
                entryFuelExact := fuelExact.1
                instructionFuelExact := fuelExact.2.1
                captureFuelExact := fuelExact.2.2.1
                returnFuelExact := fuelExact.2.2.2
              }
            else none
          else none

def exactNativeX87ReplayFixedTemplateStaticExecutionOfIsSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (checked :
      (exactNativeX87ReplayFixedTemplateStaticExecution? runtimeTarget).isSome =
        true) :
    ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget := by
  cases exact :
      exactNativeX87ReplayFixedTemplateStaticExecution? runtimeTarget with
  | none => simp [exact] at checked
  | some execution => exact execution

/-- Finite inventory of state-independent fixed-template decode artifacts.
This is the only target-indexed evidence generated packs need to provide. -/
structure ExactNativeX87ReplayFixedTemplateStaticInventory
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs) where
  forTarget : ∀ runtimeTarget ∈ inventory.targets,
    Nonempty (ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)

structure ExactNativeX87ReplayFixedTemplateSemanticShape
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget) : Prop where
  entry :
    kernelMixedReplayTemplateRoles? pe static.mixedReplay.entry =
      some (nativeX87ReplayFixedTemplateEntryRoles table pe
        runtimeTarget.target.frameMapping)
  instruction :
    kernelMixedReplayTemplateRoles? pe static.mixedReplay.instruction =
      some (nativeX87ReplayFixedTemplateInstructionRoles
        runtimeTarget.target.frameMapping static.semanticPlan.command)
  capture :
    kernelMixedReplayTemplateRoles? pe static.mixedReplay.capture =
      some (nativeX87ReplayFixedTemplateCaptureRoles table pe
        runtimeTarget.target.frameMapping)
  returnPath :
    kernelMixedReplayTemplateRoles? pe static.mixedReplay.returnPath =
      some (nativeX87ReplayFixedTemplateReturnRoles
        runtimeTarget.target.frameMapping)

theorem ExactNativeX87ReplayFixedTemplateStaticExecution.semanticShape
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget) :
    ExactNativeX87ReplayFixedTemplateSemanticShape runtimeTarget static := by
  have shape := static.semanticPlanExact
  unfold nativeX87ReplayFixedTemplateSemanticPlan? at shape
  simp only [Option.bind_eq_bind] at shape
  rw [Option.bind_eq_some_iff] at shape
  obtain ⟨entry, entryExact, shape⟩ := shape
  split at shape <;> try contradiction
  rw [Option.bind_eq_some_iff] at shape
  obtain ⟨instruction, instructionExact, shape⟩ := shape
  split at shape <;> try contradiction
  split at shape <;> try contradiction
  simp only [Option.bind_some] at shape
  split at shape <;> try contradiction
  rw [Option.bind_eq_some_iff] at shape
  obtain ⟨capture, captureExact, shape⟩ := shape
  split at shape <;> try contradiction
  rw [Option.bind_eq_some_iff] at shape
  obtain ⟨returnPath, returnExact, shape⟩ := shape
  split at shape <;> try contradiction
  injection shape
  classical
  simp only [bne_iff_ne, beq_iff_eq] at *
  refine {
    entry := ?_
    instruction := ?_
    capture := ?_
    returnPath := ?_
  } <;> simp_all [NativeX87ReplayFixedTemplateSemanticPlan.command]

/-- One ordinary static handle determines the exact arbitrary-state transition
without another PE decode or static symbolic-execution pass. -/
theorem ExactKernelMixedReplayStaticStep.ordinary_semanticStep
    (instruction : KernelInstruction)
    (specializedDecodersClear :
      KernelMixedReplayInstruction.specializedDecodersClear pe instruction =
        true)
    (decoded : DecodedInstruction)
    (decodedExact : instruction.decode? pe = some decoded)
    (undefinedSlot : Nat) (input : MachineState) :
    (KernelMixedReplayInstruction.ordinary instruction).semanticStep pe imports
        undefinedSlot input =
      match executeInstruction pe imports instruction.rva undefinedSlot decoded
          initialSymbolic with
      | none => .fault
      | some result =>
          StageA.Relational.SymbolicSoundness.executeInstructionResult
            (instruction.rva + decoded.size) undefinedSlot input result := by
  rw [KernelMixedReplayInstruction.semanticStep,
    StageA.Relational.SymbolicSoundness.KernelInstruction.semanticStep,
    decodedExact]
  rfl

/-- One frame handle similarly exposes the reviewed physical frame operation
without re-decoding its exact bytes. -/
theorem ExactKernelMixedReplayStaticStep.x87Frame_semanticStep
    (instruction : KernelX87FrameInstruction)
    (decoded : KernelX87FrameDecoded)
    (decodedExact : instruction.decode? pe = some decoded)
    (undefinedSlot : Nat) (input : MachineState) :
    (KernelMixedReplayInstruction.x87Frame instruction).semanticStep pe imports
        undefinedSlot input =
      match executeKernelX87Frame? decoded input with
      | none => .fault
      | some after =>
          .running (instruction.rva + decoded.size) (undefinedSlot + 1) after := by
  rw [KernelMixedReplayInstruction.semanticStep, decodedExact]
  rfl

/-- The command handle fixes the reviewed x87 descriptor while retaining the
source state's parametric x87 semantics implementation. -/
theorem ExactKernelMixedReplayStaticStep.x87Command_semanticStep
    (instruction : KernelX87CommandInstruction)
    (frameDecoderClear :
      KernelMixedReplayInstruction.frameDecoderClear pe instruction = true)
    (decoded : StageA.Relational.X87.DecodedCommand)
    (decodedExact : instruction.decode? pe = some decoded)
    (undefinedSlot : Nat) (input : MachineState) :
    (KernelMixedReplayInstruction.x87Command instruction).semanticStep pe imports
        undefinedSlot input =
      match executeKernelX87Command? pe instruction.rva undefinedSlot input
          decoded with
      | none => .fault
      | some after => after := by
  rw [KernelMixedReplayInstruction.semanticStep, decodedExact]
  rfl

def NativeX87ReplayTemplateRole.semanticStep
    (pe : PE32) (imports : List PEImport) :
    NativeX87ReplayTemplateRole -> Nat -> MachineState -> PE32InstructionExecution
  | .ordinary rva instruction size, undefinedSlot, input =>
      let decoded : DecodedInstruction := { instruction, size, trailing := [] }
      match executeInstruction pe imports rva undefinedSlot decoded initialSymbolic with
      | none => .fault
      | some result =>
          StageA.Relational.SymbolicSoundness.executeInstructionResult
            (rva + size) undefinedSlot input result
  | .x87Frame rva decoded, undefinedSlot, input =>
      match executeKernelX87Frame? decoded input with
      | none => .fault
      | some after => .running (rva + decoded.size) (undefinedSlot + 1) after
  | .x87Command rva decoded, undefinedSlot, input =>
      match executeKernelX87Command? pe rva undefinedSlot input decoded with
      | none => .fault
      | some after => after

def nativeX87ReplayOrdinaryState (behavior : SymbolicBehavior)
    (input : MachineState) : MachineState :=
  concreteBehaviorNextMachineState (behavior.eval input) input

@[simp] theorem nativeX87ReplayOrdinaryState_undefinedValue
    (behavior : SymbolicBehavior) (input : MachineState) :
    (nativeX87ReplayOrdinaryState behavior input).undefinedValue =
      input.undefinedValue :=
  rfl

@[simp] theorem nativeX87ReplayOrdinaryState_x87Physical
    (behavior : SymbolicBehavior) (input : MachineState) :
    (nativeX87ReplayOrdinaryState behavior input).x87Physical =
      input.x87Physical :=
  rfl

@[simp] theorem nativeX87ReplayOrdinaryState_x87Semantics
    (behavior : SymbolicBehavior) (input : MachineState) :
    (nativeX87ReplayOrdinaryState behavior input).x87Semantics =
      input.x87Semantics :=
  rfl

@[simp] theorem nativeX87ReplayOrdinaryState_fsBase
    (behavior : SymbolicBehavior) (input : MachineState) :
    (nativeX87ReplayOrdinaryState behavior input).fsBase = input.fsBase :=
  rfl

private theorem updateFlag_inputBit
    (word : Word) (index : Nat) (bounded : index < 32) :
    updateFlag word index
        (some (word.extractLsb' index 1 == BitVec.ofNat 1 1)) =
      word := by
  rw [← BitVec.getElem_eq_extractLsb' word index bounded]
  have maskExact :
      BitVec.ofNat 32 (2 ^ index) = BitVec.twoPow 32 index := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_twoPow]
  apply BitVec.eq_of_getElem_eq
  intro observed observedBounded
  by_cases same : observed = index
  · subst observed
    cases bit : word[index] <;>
      simp [updateFlag, bit, maskExact, bounded]
  · cases bit : word[index] <;>
      simp [updateFlag, bit, maskExact, observedBounded, same]

private theorem initialSymbolicFlags_eval (input : MachineState) :
    (initialSymbolic.flags.map (FlagsExpr.eval input)).getD input.eflags =
      input.eflags := by
  simp [initialSymbolic, FlagsExpr.eval, BoolExpr.eval]
  rw [updateFlag_inputBit _ 0 (by decide)]
  rw [updateFlag_inputBit _ 2 (by decide)]
  rw [show updateFlag input.eflags 4 none = input.eflags by rfl]
  rw [updateFlag_inputBit _ 6 (by decide)]
  rw [updateFlag_inputBit _ 7 (by decide)]
  rw [updateFlag_inputBit _ 11 (by decide)]

private theorem initialSymbolicEflagsExpression_eval
    (input : MachineState) :
    initialSymbolic.eflagsExpression.eval input = input.eflags := by
  exact initialSymbolicEflagsEval input

private theorem updateFlagExpression_eval_sourceBit
    (input : MachineState) (base source : Expr) (index : Nat)
    (bounded : index < 32)
    (baseExact : base.eval input = source.eval input) :
    (updateFlagExpression base index (some (.bit source index))).eval input =
      source.eval input := by
  have powerBounded : 2 ^ index < 2 ^ 32 :=
    Nat.pow_lt_pow_right (by decide) bounded
  have clearMaskBounded :
      2 ^ 32 - 1 - 2 ^ index < 2 ^ 32 := by
    exact Nat.lt_of_le_of_lt (Nat.sub_le _ _) (by decide)
  have clearMaskExact :
      BitVec.ofNat 32 (2 ^ 32 - 1 - 2 ^ index) =
        ~~~(BitVec.twoPow 32 index) := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_twoPow, Nat.mod_eq_of_lt powerBounded,
      Nat.mod_eq_of_lt clearMaskBounded]
  have sourceTestBit :
      (source.eval input).toNat.testBit index =
        (source.eval input)[index] :=
    (BitVec.getElem_eq_testBit_toNat
      (source.eval input) index bounded).symm
  apply BitVec.eq_of_getElem_eq
  intro observed observedBounded
  by_cases same : observed = index
  · subst observed
    cases bit : (source.eval input)[index] <;>
      simp [updateFlagExpression, StageA.Formal.Expr.eval, BoolExpr.eval,
        BoolExpr.toWord_eval, baseExact, clearMaskExact, sourceTestBit,
        bounded, bit]
  · cases bit : (source.eval input)[index] <;>
      simp [updateFlagExpression, StageA.Formal.Expr.eval, BoolExpr.eval,
        BoolExpr.toWord_eval, baseExact, clearMaskExact, observedBounded,
        sourceTestBit, same, bit] <;>
      omega

private theorem flagsFromWordExpression_apply_self
    (input : MachineState) (word : Expr) :
    ((flagsFromWordExpression word).applyToExpression word).eval input =
      word.eval input := by
  let carry := updateFlagExpression word 0 (some (.bit word 0))
  let parity := updateFlagExpression carry 2 (some (.bit word 2))
  let auxiliary := updateFlagExpression parity 4 (some (.bit word 4))
  let zero := updateFlagExpression auxiliary 6 (some (.bit word 6))
  let sign := updateFlagExpression zero 7 (some (.bit word 7))
  have carryExact : carry.eval input = word.eval input :=
    updateFlagExpression_eval_sourceBit input word word 0 (by decide) rfl
  have parityExact : parity.eval input = word.eval input :=
    updateFlagExpression_eval_sourceBit input carry word 2
      (by decide) carryExact
  have auxiliaryExact : auxiliary.eval input = word.eval input :=
    updateFlagExpression_eval_sourceBit input parity word 4
      (by decide) parityExact
  have zeroExact : zero.eval input = word.eval input :=
    updateFlagExpression_eval_sourceBit input auxiliary word 6
      (by decide) auxiliaryExact
  have signExact : sign.eval input = word.eval input :=
    updateFlagExpression_eval_sourceBit input zero word 7
      (by decide) zeroExact
  change
    (updateFlagExpression sign 11 (some (.bit word 11))).eval input =
      word.eval input
  exact updateFlagExpression_eval_sourceBit input sign word 11
    (by decide) signExact

private theorem nativeX87ReplayOrdinaryState_eflags_of_initialFlags
    (behavior : SymbolicBehavior) (input : MachineState)
    (baseExact : behavior.flagsBase = none)
    (flagsExact : behavior.flags = initialSymbolic.flags) :
    (nativeX87ReplayOrdinaryState behavior input).eflags = input.eflags := by
  change
    (match behavior.flagsBase, behavior.flags with
    | none, none => input.eflags
    | none, some flags => flags.eval input
    | some base, none => base.eval input
    | some base, some flags => (flags.applyToExpression base).eval input) =
      input.eflags
  rw [baseExact, flagsExact]
  exact initialSymbolicFlags_eval input

theorem NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
    (rva size undefinedSlot : Nat) (instruction : Instruction)
    (behavior : SymbolicBehavior) (input : MachineState)
    (executeExact :
      executeInstruction pe imports rva undefinedSlot
          { instruction, size, trailing := [] } initialSymbolic =
        some (.next behavior))
    (outcomeExact : behavior.outcome = none) :
    (NativeX87ReplayTemplateRole.ordinary rva instruction size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayOrdinaryState behavior input) := by
  rw [NativeX87ReplayTemplateRole.semanticStep, executeExact]
  simp only [StageA.Relational.SymbolicSoundness.executeInstructionResult,
    InstructionResult.next.injEq]
  change
    (match (behavior.eval input).outcome with
    | some _ => PE32InstructionExecution.fault
    | none =>
        PE32InstructionExecution.running (rva + size) (undefinedSlot + 1)
          (nativeX87ReplayOrdinaryState behavior input)) =
      PE32InstructionExecution.running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayOrdinaryState behavior input)
  have evaluatedOutcome : (behavior.eval input).outcome = none := by
    simp [SymbolicBehavior.eval, outcomeExact]
  rw [evaluatedOutcome]

def nativeX87ReplayPushRegBehavior (source : Reg) : SymbolicBehavior :=
  let stack := initialSymbolic.registers.esp.offset (2 ^ 32 - 4)
  let symbolic := initialSymbolic.write32 stack
    (initialSymbolic.registers.get source)
  {
    symbolic with registers := symbolic.registers.set .esp stack
  }

theorem nativeX87ReplayPushRegBehavior_exact
    (source : Reg) :
    nativeX87ReplayPushRegBehavior source = {
      initialSymbolic with
        registers := initialSymbolic.registers.set .esp
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4))
        writes := [(
          initialSymbolic.registers.esp.offset (2 ^ 32 - 4),
          initialSymbolic.registers.get source)]
    } := by
  cases source <;>
    simp [nativeX87ReplayPushRegBehavior, SymbolicBehavior.write32,
      initialSymbolic, Registers.set, Registers.get]

theorem nativeX87ReplayPushRegBehavior_outcome
    (source : Reg) :
    (nativeX87ReplayPushRegBehavior source).outcome = none := by
  rw [nativeX87ReplayPushRegBehavior_exact]
  rfl

def nativeX87ReplayPushRegState (source : Reg)
    (input : MachineState) : MachineState :=
  concreteBehaviorNextMachineState
    ((nativeX87ReplayPushRegBehavior source).eval input) input

@[simp] theorem nativeX87ReplayPushRegState_registers
    (source : Reg) (input : MachineState) :
    (nativeX87ReplayPushRegState source input).registers =
      input.registers.set .esp
        (input.registers.esp - BitVec.ofNat 32 4) := by
  rw [nativeX87ReplayPushRegState, nativeX87ReplayPushRegBehavior_exact]
  simp [concreteBehaviorNextMachineState, SymbolicBehavior.eval,
    initialSymbolic, Registers.set, Registers.get, Expr.offset,
    Expr.addNormalized, StageA.Formal.Expr.eval]

@[simp] theorem nativeX87ReplayPushRegState_memory
    (source : Reg) (input : MachineState) :
    (nativeX87ReplayPushRegState source input).memory =
      input.memory.write32
        (input.registers.esp - BitVec.ofNat 32 4)
        (input.registers.get source) := by
  rw [nativeX87ReplayPushRegState, nativeX87ReplayPushRegBehavior_exact]
  cases source <;>
    simp [concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      initialSymbolic, Registers.set, Registers.get, Expr.offset,
      Expr.addNormalized, StageA.Formal.Expr.eval, StageA.Formal.applyWrites]

@[simp] theorem nativeX87ReplayPushRegState_eflags
    (source : Reg) (input : MachineState) :
    (nativeX87ReplayPushRegState source input).eflags = input.eflags := by
  unfold nativeX87ReplayPushRegState
  apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags
  · rw [nativeX87ReplayPushRegBehavior_exact]
    rfl
  · rw [nativeX87ReplayPushRegBehavior_exact]

@[simp] theorem nativeX87ReplayPushRegState_x87Physical
    (source : Reg) (input : MachineState) :
    (nativeX87ReplayPushRegState source input).x87Physical =
      input.x87Physical := by
  simp [nativeX87ReplayPushRegState, concreteBehaviorNextMachineState,
    nativeX87ReplayPushRegBehavior, SymbolicBehavior.eval, initialSymbolic]

@[simp] theorem nativeX87ReplayPushRegState_x87Semantics
    (source : Reg) (input : MachineState) :
    (nativeX87ReplayPushRegState source input).x87Semantics =
      input.x87Semantics := by
  simp [nativeX87ReplayPushRegState, concreteBehaviorNextMachineState,
    nativeX87ReplayPushRegBehavior, SymbolicBehavior.eval, initialSymbolic]

theorem NativeX87ReplayTemplateRole.semanticStep_pushReg
    (rva size undefinedSlot : Nat) (source : Reg) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva (.pushReg source) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPushRegState source input) := by
  have outcome :
      ((nativeX87ReplayPushRegBehavior source).eval input).outcome = none := by
    simp [SymbolicBehavior.eval, nativeX87ReplayPushRegBehavior_outcome]
  change
    (match
      ((nativeX87ReplayPushRegBehavior source).eval input).outcome with
    | some _ => PE32InstructionExecution.fault
    | none => PE32InstructionExecution.running
        (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPushRegState source input)) =
      PE32InstructionExecution.running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPushRegState source input)
  rw [outcome]

def nativeX87ReplayMovFromOperandBehavior (destination : Reg)
    (source : Operand32) : SymbolicBehavior := {
  initialSymbolic with
    registers := initialSymbolic.registers.set destination
      (readOperand32 initialSymbolic source)
}

def nativeX87ReplayMovFromOperandState (destination : Reg)
    (source : Operand32) (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayMovFromOperandBehavior destination source) input

@[simp] theorem nativeX87ReplayMovFromOperandState_memory
    (destination : Reg) (source : Operand32) (input : MachineState) :
    (nativeX87ReplayMovFromOperandState destination source input).memory =
      input.memory := by
  rfl

@[simp] theorem nativeX87ReplayMovFromOperandState_registers
    (destination : Reg) (source : Operand32) (input : MachineState) :
    (nativeX87ReplayMovFromOperandState destination source input).registers =
      input.registers.set destination
        ((readOperand32 initialSymbolic source).eval input) := by
  cases destination <;> rfl

@[simp] theorem nativeX87ReplayMovFromOperandState_eflags
    (destination : Reg) (source : Operand32) (input : MachineState) :
    (nativeX87ReplayMovFromOperandState destination source input).eflags =
      input.eflags := by
  apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags <;>
    rfl

@[simp] theorem nativeX87ReplayMovFromOperandState_register
    (destination : Reg) (source : Operand32) (input : MachineState) :
    (nativeX87ReplayMovFromOperandState destination source input).registers.get
        destination =
      (readOperand32 initialSymbolic source).eval input := by
  cases destination <;>
    simp [nativeX87ReplayMovFromOperandState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayMovFromOperandBehavior,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      Registers.set, Registers.get]

theorem nativeX87ReplayMovFromOperandState_register_other
    (destination register : Reg) (source : Operand32) (input : MachineState)
    (different : register ≠ destination) :
    (nativeX87ReplayMovFromOperandState destination source input).registers.get
        register =
      input.registers.get register := by
  cases destination <;> cases register <;>
    simp_all [nativeX87ReplayMovFromOperandState_registers,
      Registers.set, Registers.get]

private theorem nativeX87ReplayMovFromEaxMemoryState_registers
    (destination : Reg) (displacement : Nat) (input : MachineState)
    (base value : Word)
    (eaxExact : input.registers.eax = base)
    (valueRead :
      Memory.read32 input.memory
          (base + BitVec.ofNat 32 displacement) = value) :
    (nativeX87ReplayMovFromOperandState destination
      (nativeX87ReplayMemory (some .eax) displacement) input).registers =
        input.registers.set destination value := by
  have valueExact :
      (readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement)).eval input =
        value := by
    calc
      _ = Memory.read32 input.memory
          (input.registers.get .eax +
            BitVec.ofNat 32 displacement) :=
        readNativeX87ReplayMemorySome .eax displacement input
      _ = Memory.read32 input.memory
          (base + BitVec.ofNat 32 displacement) := by
        exact congrArg (Memory.read32 input.memory)
          (congrArg (fun address =>
            address + BitVec.ofNat 32 displacement)
            (by simpa [Registers.get] using eaxExact))
      _ = value := valueRead
  calc
    _ = input.registers.set destination
        ((readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement)).eval input) :=
      nativeX87ReplayMovFromOperandState_registers destination _ input
    _ = input.registers.set destination value :=
      congrArg (input.registers.set destination) valueExact

theorem NativeX87ReplayTemplateRole.semanticStep_movFromOperand
    (rva size undefinedSlot : Nat) (destination : Reg)
    (source : Operand32) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.movFromOperand destination source) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayMovFromOperandState destination source input) := by
  rfl

def nativeX87ReplayMovToMemoryBehavior (destination : Addressing)
    (source : Reg) : SymbolicBehavior :=
  initialSymbolic.write32 (destination.expression initialSymbolic.registers)
    (initialSymbolic.registers.get source)

def nativeX87ReplayMovToMemoryState (destination : Addressing)
    (source : Reg) (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayMovToMemoryBehavior destination source) input

@[simp] theorem nativeX87ReplayMovToMemoryState_memory
    (destination : Addressing) (source : Reg) (input : MachineState) :
    (nativeX87ReplayMovToMemoryState destination source input).memory =
      input.memory.write32
        ((destination.expression initialSymbolic.registers).eval input)
        (input.registers.get source) := by
  cases source <;>
    simp [nativeX87ReplayMovToMemoryState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayMovToMemoryBehavior, concreteBehaviorNextMachineState,
      SymbolicBehavior.write32, SymbolicBehavior.eval, initialSymbolic,
      StageA.Formal.applyWrites, StageA.Formal.Expr.eval, Registers.get]

@[simp] theorem nativeX87ReplayMovToMemoryState_registers
    (destination : Addressing) (source : Reg) (input : MachineState) :
    (nativeX87ReplayMovToMemoryState destination source input).registers =
      input.registers := by
  apply Registers.eq_of_fields <;>
    simp [nativeX87ReplayMovToMemoryState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayMovToMemoryBehavior, concreteBehaviorNextMachineState,
      SymbolicBehavior.write32, SymbolicBehavior.eval, initialSymbolic,
      StageA.Formal.Expr.eval]
  all_goals split <;> rfl

@[simp] theorem nativeX87ReplayMovToMemoryState_eflags
    (destination : Addressing) (source : Reg) (input : MachineState) :
    (nativeX87ReplayMovToMemoryState destination source input).eflags =
      input.eflags := by
  apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags
  all_goals
    simp only [nativeX87ReplayMovToMemoryBehavior, SymbolicBehavior.write32]
    split <;> rfl

theorem NativeX87ReplayTemplateRole.semanticStep_movToMemory
    (rva size undefinedSlot : Nat) (destination : Addressing)
    (source : Reg) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.movToOperand (.memory destination) source) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayMovToMemoryState destination source input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · simp [nativeX87ReplayMovToMemoryBehavior,
      SymbolicBehavior.write32, initialSymbolic]
    split <;> rfl

def nativeX87ReplayMovImmediateMemoryBehavior (destination : Addressing)
    (value : Nat) : SymbolicBehavior :=
  initialSymbolic.write32 (destination.expression initialSymbolic.registers)
    (.constant value)

def nativeX87ReplayMovImmediateMemoryState (destination : Addressing)
    (value : Nat) (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayMovImmediateMemoryBehavior destination value) input

@[simp] private theorem nativeX87ReplayMovImmediateMemoryState_memory
    (destination : Addressing) (value : Nat) (input : MachineState) :
    (nativeX87ReplayMovImmediateMemoryState destination value input).memory =
      input.memory.write32
        ((destination.expression initialSymbolic.registers).eval input)
        (BitVec.ofNat 32 value) := by
  simp [nativeX87ReplayMovImmediateMemoryState, nativeX87ReplayOrdinaryState,
    nativeX87ReplayMovImmediateMemoryBehavior,
    concreteBehaviorNextMachineState, SymbolicBehavior.write32,
    SymbolicBehavior.eval, initialSymbolic, StageA.Formal.applyWrites,
    StageA.Formal.Expr.eval]

@[simp] private theorem nativeX87ReplayMovImmediateMemoryState_registers
    (destination : Addressing) (value : Nat) (input : MachineState) :
    (nativeX87ReplayMovImmediateMemoryState destination value input).registers =
      input.registers := by
  apply Registers.eq_of_fields <;>
    simp [nativeX87ReplayMovImmediateMemoryState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayMovImmediateMemoryBehavior,
      concreteBehaviorNextMachineState, SymbolicBehavior.write32,
      SymbolicBehavior.eval, initialSymbolic, Registers.get,
      StageA.Formal.Expr.eval]

theorem NativeX87ReplayTemplateRole.semanticStep_movImmediateMemory
    (rva size undefinedSlot : Nat) (destination : Addressing)
    (value : Nat) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.movImmediate (.memory destination) value) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayMovImmediateMemoryState destination value input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · simp [nativeX87ReplayMovImmediateMemoryBehavior,
      SymbolicBehavior.write32, initialSymbolic]

def nativeX87ReplayPushOperandBehavior (source : Operand32) :
    SymbolicBehavior :=
  let stack := initialSymbolic.registers.esp.offset (2 ^ 32 - 4)
  let symbolic := initialSymbolic.write32 stack
    (readOperand32 initialSymbolic source)
  {
    symbolic with registers := symbolic.registers.set .esp stack
  }

def nativeX87ReplayPushOperandState (source : Operand32)
    (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayPushOperandBehavior source) input

@[simp] theorem nativeX87ReplayPushOperandState_eflags
    (source : Operand32) (input : MachineState) :
    (nativeX87ReplayPushOperandState source input).eflags = input.eflags := by
  apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags
  all_goals
    simp only [nativeX87ReplayPushOperandBehavior, SymbolicBehavior.write32]
    split <;> rfl

@[simp] theorem nativeX87ReplayPushOperandState_esp
    (source : Operand32) (input : MachineState) :
    (nativeX87ReplayPushOperandState source input).registers.esp =
      input.registers.esp - BitVec.ofNat 32 4 := by
  simp [nativeX87ReplayPushOperandState, nativeX87ReplayOrdinaryState,
    nativeX87ReplayPushOperandBehavior, concreteBehaviorNextMachineState,
    SymbolicBehavior.write32, SymbolicBehavior.eval, initialSymbolic,
    Registers.set, Registers.get, Expr.offset, Expr.addNormalized,
    StageA.Formal.Expr.eval]

private theorem nativeX87ReplayPushMemoryEaxBehavior_exact
    (displacement : Nat)
    (distinct :
      readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ≠
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4))) :
    nativeX87ReplayPushOperandBehavior
        (nativeX87ReplayMemory (some .eax) displacement) = {
      initialSymbolic with
        registers := initialSymbolic.registers.set .esp
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4))
        writes := [(
          initialSymbolic.registers.esp.offset (2 ^ 32 - 4),
          readOperand32 initialSymbolic
            (nativeX87ReplayMemory (some .eax) displacement))]
    } := by
  have distinctBool :
      (readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ==
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4))) = false := by
    simpa [beq_iff_eq] using distinct
  have noWrites : initialSymbolic.writes = [] := rfl
  unfold nativeX87ReplayPushOperandBehavior SymbolicBehavior.write32
  simp only [noWrites, List.filter_nil, List.all_nil, Bool.and_true,
    distinctBool, Bool.false_eq_true, if_false, List.nil_append]

@[simp] private theorem nativeX87ReplayPushMemoryEaxState_memory
    (displacement : Nat)
    (distinct :
      readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ≠
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4)))
    (input : MachineState) :
    (nativeX87ReplayPushOperandState
        (nativeX87ReplayMemory (some .eax) displacement) input).memory =
      input.memory.write32
        (input.registers.esp - BitVec.ofNat 32 4)
        ((readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement)).eval input) := by
  rw [nativeX87ReplayPushOperandState,
    nativeX87ReplayPushMemoryEaxBehavior_exact displacement distinct]
  simp [nativeX87ReplayOrdinaryState, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, Registers.get, Expr.offset,
    Expr.addNormalized, StageA.Formal.applyWrites,
    StageA.Formal.Expr.eval]

private theorem nativeX87ReplayPushMemoryEaxState_memory_of_read
    (displacement : Nat)
    (distinct :
      readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ≠
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4)))
    (input : MachineState) (base value : Word)
    (baseExact : input.registers.get .eax = base)
    (valueExact :
      Memory.read32 input.memory
        (base + BitVec.ofNat 32 displacement) = value) :
    (nativeX87ReplayPushOperandState
        (nativeX87ReplayMemory (some .eax) displacement) input).memory =
      input.memory.write32
        (input.registers.esp - BitVec.ofNat 32 4) value := by
  rw [nativeX87ReplayPushMemoryEaxState_memory displacement distinct]
  congr 1
  exact readNativeX87ReplayMemorySome_eq .eax displacement input base value
    baseExact valueExact

private theorem nativeX87ReplayPushMemoryEaxState_top_of_read
    (displacement : Nat)
    (distinct :
      readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ≠
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4)))
    (input : MachineState) (base value : Word)
    (baseExact : input.registers.get .eax = base)
    (valueExact :
      Memory.read32 input.memory
        (base + BitVec.ofNat 32 displacement) = value) :
    Memory.read32
        (nativeX87ReplayPushOperandState
          (nativeX87ReplayMemory (some .eax) displacement) input).memory
        (nativeX87ReplayPushOperandState
          (nativeX87ReplayMemory (some .eax) displacement) input).registers.esp =
      value := by
  rw [nativeX87ReplayPushMemoryEaxState_memory_of_read displacement distinct
    input base value baseExact valueExact]
  rw [nativeX87ReplayPushOperandState_esp]
  exact Memory.read32_write32_same _ _ _

@[simp] private theorem nativeX87ReplayPushMemoryEaxState_registers
    (displacement : Nat)
    (distinct :
      readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ≠
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4)))
    (input : MachineState) :
    (nativeX87ReplayPushOperandState
        (nativeX87ReplayMemory (some .eax) displacement) input).registers =
      { input.registers with
          esp := input.registers.esp - BitVec.ofNat 32 4 } := by
  rw [nativeX87ReplayPushOperandState,
    nativeX87ReplayPushMemoryEaxBehavior_exact displacement distinct]
  simp [nativeX87ReplayOrdinaryState, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, Registers.set, Registers.get,
    Expr.offset, Expr.addNormalized, StageA.Formal.Expr.eval]

theorem NativeX87ReplayTemplateRole.semanticStep_pushOperand
    (rva size undefinedSlot : Nat) (source : Operand32)
    (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.pushOperand source) size).semanticStep pe imports
        undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPushOperandState source input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · simp [nativeX87ReplayPushOperandBehavior, SymbolicBehavior.write32,
      initialSymbolic]
    split <;> rfl

def nativeX87ReplayPopRegBehavior (destination : Reg) : SymbolicBehavior :=
  let value := symbolicRead32 initialSymbolic initialSymbolic.registers.esp
  let stack := initialSymbolic.registers.esp.offset 4
  {
    initialSymbolic with
      registers := (initialSymbolic.registers.set destination value).set
        .esp stack
  }

def nativeX87ReplayPopRegState (destination : Reg)
    (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayPopRegBehavior destination) input

@[simp] theorem nativeX87ReplayPopRegState_memory
    (destination : Reg) (input : MachineState) :
    (nativeX87ReplayPopRegState destination input).memory = input.memory := by
  rfl

@[simp] theorem nativeX87ReplayPopRegState_registers
    (destination : Reg) (input : MachineState) :
    (nativeX87ReplayPopRegState destination input).registers =
      (input.registers.set destination
        (Memory.read32 input.memory input.registers.esp)).set .esp
          (input.registers.esp + BitVec.ofNat 32 4) := by
  cases destination <;>
    simp [nativeX87ReplayPopRegState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayPopRegBehavior, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, symbolicRead32,
      exactWrite32WithDisjointTail?, Registers.set, Registers.get,
      Expr.offset, Expr.addNormalized,
      StageA.Formal.Expr.eval]

@[simp] private theorem nativeX87ReplayPopRegState_esp
    (destination : Reg) (input : MachineState) :
    (nativeX87ReplayPopRegState destination input).registers.esp =
      input.registers.esp + BitVec.ofNat 32 4 := by
  rw [nativeX87ReplayPopRegState_registers]
  cases destination <;> rfl

@[simp] theorem nativeX87ReplayPopRegState_eflags
    (destination : Reg) (input : MachineState) :
    (nativeX87ReplayPopRegState destination input).eflags = input.eflags := by
  apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags <;>
    rfl

theorem NativeX87ReplayTemplateRole.semanticStep_popReg
    (rva size undefinedSlot : Nat) (destination : Reg)
    (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.popReg destination) size).semanticStep pe imports
        undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPopRegState destination input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · rfl

def nativeX87ReplayPushFlagsBehavior : SymbolicBehavior :=
  let stack := initialSymbolic.registers.esp.offset (2 ^ 32 - 4)
  let value := .bitAnd initialSymbolic.eflagsExpression
    (.constant 0xfffcffff)
  let symbolic := initialSymbolic.write32 stack value
  {
    symbolic with registers := symbolic.registers.set .esp stack
  }

def nativeX87ReplayPushFlagsState (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState nativeX87ReplayPushFlagsBehavior input

@[simp] theorem nativeX87ReplayPushFlagsState_eflags
    (input : MachineState) :
    (nativeX87ReplayPushFlagsState input).eflags = input.eflags := by
  apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags
  · rfl
  · rfl

theorem NativeX87ReplayTemplateRole.semanticStep_pushFlags
    (rva size undefinedSlot : Nat) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva .pushFlags size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPushFlagsState input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · simp [nativeX87ReplayPushFlagsBehavior, SymbolicBehavior.write32,
      initialSymbolic]

def nativeX87ReplayPopFlagsBehavior : SymbolicBehavior :=
  let stack := initialSymbolic.registers.esp
  let popped := symbolicRead32 initialSymbolic stack
  let restored := popFlagsCpl3Expression initialSymbolic.eflagsExpression popped
  {
    initialSymbolic with
      registers := initialSymbolic.registers.set .esp (stack.offset 4)
      flagsBase := some restored
      flags := some (flagsFromWordExpression restored)
      comparison := none
  }

def nativeX87ReplayPopFlagsState (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState nativeX87ReplayPopFlagsBehavior input

@[simp] theorem nativeX87ReplayPopFlagsState_memory
    (input : MachineState) :
    (nativeX87ReplayPopFlagsState input).memory = input.memory := by
  rfl

@[simp] theorem nativeX87ReplayPopFlagsState_registers
    (input : MachineState) :
    (nativeX87ReplayPopFlagsState input).registers =
      input.registers.set .esp
        (input.registers.esp + BitVec.ofNat 32 4) := by
  simp [nativeX87ReplayPopFlagsState, nativeX87ReplayOrdinaryState,
    nativeX87ReplayPopFlagsBehavior, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, symbolicRead32, Registers.set,
    Registers.get, Expr.offset, Expr.addNormalized,
      StageA.Formal.Expr.eval]

theorem nativeX87ReplayPopFlagsState_eflags
    (input : MachineState) :
    (nativeX87ReplayPopFlagsState input).eflags =
      (popFlagsCpl3Expression initialSymbolic.eflagsExpression
        (.constant
          (Memory.read32 input.memory input.registers.esp).toNat)).eval
        input := by
  simp [nativeX87ReplayPopFlagsState, nativeX87ReplayOrdinaryState,
    nativeX87ReplayPopFlagsBehavior, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, symbolicRead32,
    exactWrite32WithDisjointTail?, Registers.get,
    flagsFromWordExpression_apply_self, SymbolicBehavior.eflagsExpression,
    popFlagsCpl3Expression, updateFlagExpression, Expr.offset,
    Expr.addNormalized, StageA.Formal.Expr.eval, BoolExpr.eval,
    BoolExpr.toWord_eval]
  rfl

theorem NativeX87ReplayTemplateRole.semanticStep_popFlags
    (rva size undefinedSlot : Nat) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva .popFlags size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayPopFlagsState input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · rfl

def nativeX87ReplayClearDirectionBehavior : SymbolicBehavior :=
  let base := Expr.bitAnd initialSymbolic.eflagsExpression
    (.constant 0xfffffbff)
  {
    initialSymbolic with
      flagsBase := some base
      flags := none
      comparison := none
  }

def nativeX87ReplayClearDirectionState (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState nativeX87ReplayClearDirectionBehavior input

@[simp] private theorem nativeX87ReplayClearDirectionState_memory
    (input : MachineState) :
    (nativeX87ReplayClearDirectionState input).memory = input.memory := by
  rfl

@[simp] private theorem nativeX87ReplayClearDirectionState_registers
    (input : MachineState) :
    (nativeX87ReplayClearDirectionState input).registers = input.registers := by
  apply Registers.eq_of_fields <;>
    simp [nativeX87ReplayClearDirectionState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayClearDirectionBehavior,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      initialSymbolic, Registers.get, StageA.Formal.Expr.eval]

theorem NativeX87ReplayTemplateRole.semanticStep_clearDirection
    (rva size undefinedSlot : Nat) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva .clearDirection size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayClearDirectionState input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · rfl

theorem NativeX87ReplayTemplateRole.semanticStep_nop
    (rva size undefinedSlot : Nat) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva .nop size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayOrdinaryState initialSymbolic input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · rfl

def nativeX87ReplaySetConditionMemoryBehavior (condition : Condition)
    (destination : Addressing) : SymbolicBehavior :=
  match initialSymbolic.flags with
  | none => initialSymbolic
  | some flags =>
      match conditionExpression flags condition with
      | none => initialSymbolic
      | some conditionValue =>
          let value := Expr.ifEqual conditionValue.toWord (.constant 1)
            (.constant 1) (.constant 0)
          (writeOperand8 initialSymbolic (.memory destination) value).getD
            initialSymbolic

def nativeX87ReplaySetConditionMemoryState (condition : Condition)
    (destination : Addressing) (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplaySetConditionMemoryBehavior condition destination) input

private theorem nativeX87ReplaySetConditionMemoryState_memoryFrame
    (condition : Condition) (destination : Addressing)
    (input : MachineState) :
    MemoryAgreesOutside
      (nativeX87ReplayByteRange
        ((destination.expression initialSymbolic.registers).eval input) 4)
      (nativeX87ReplaySetConditionMemoryState condition destination input).memory
      input.memory := by
  cases condition <;>
    simp [nativeX87ReplaySetConditionMemoryState,
      nativeX87ReplayOrdinaryState,
      nativeX87ReplaySetConditionMemoryBehavior, conditionExpression,
      writeOperand8, SymbolicBehavior.write32,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      initialSymbolic, StageA.Formal.applyWrites,
      StageA.Formal.Expr.eval, BoolExpr.eval]
  all_goals
    apply MemoryAgreesOutside.write32ByteRange

private theorem nativeX87ReplayAddressing_edx_eval
    (displacement : Nat) (input : MachineState) :
    ((nativeX87ReplayAddressing (some .edx) displacement).expression
      initialSymbolic.registers).eval input =
      input.registers.edx + BitVec.ofNat 32 displacement := by
  simpa [nativeX87ReplayAddressing, Addressing.expression, initialSymbolic,
    Registers.get] using
    evalInputRegisterOffset input .edx displacement

private theorem nativeX87ReplayAddressing_edx_offset_eval
    (displacement byteOffset : Nat) (input : MachineState) :
    (((nativeX87ReplayAddressing (some .edx) displacement).expression
      initialSymbolic.registers).offset byteOffset).eval input =
      input.registers.edx + BitVec.ofNat 32 displacement +
        BitVec.ofNat 32 byteOffset := by
  simpa [nativeX87ReplayAddressing, Addressing.expression, initialSymbolic,
    Registers.get] using
    Expr.eval_inputReg_offset_offset .edx displacement byteOffset input

set_option maxHeartbeats 100000 in
private theorem nativeX87ReplaySetConditionMemoryState_memory_inputFlag
    (condition : Condition) (bit displacement : Nat) (input : MachineState)
    (conditionExact :
      conditionExpression {
        zero := some (.inputFlag 6)
        carry := some (.inputFlag 0)
        sign := some (.inputFlag 7)
        overflow := some (.inputFlag 11)
        parity := some (.inputFlag 2)
      } condition = some (BoolExpr.inputFlag bit)) :
    (nativeX87ReplaySetConditionMemoryState condition
      (nativeX87ReplayAddressing (some .edx) displacement) input).memory =
      input.memory.write32
        (input.registers.edx + BitVec.ofNat 32 displacement)
        ((Memory.read32 input.memory
            (input.registers.edx + BitVec.ofNat 32 displacement) &&&
              BitVec.ofNat 32 0xffffff00) |||
          BitVec.ofNat 32 (input.eflags.extractLsb' bit 1).toNat) := by
  have addressExact :=
    nativeX87ReplayAddressing_edx_eval displacement input
  have byteOneExact :=
    nativeX87ReplayAddressing_edx_offset_eval displacement 1 input
  have byteTwoExact :=
    nativeX87ReplayAddressing_edx_offset_eval displacement 2 input
  have byteThreeExact :=
    nativeX87ReplayAddressing_edx_offset_eval displacement 3 input
  simp only [initialSymbolic] at addressExact byteOneExact byteTwoExact byteThreeExact
  simp [nativeX87ReplaySetConditionMemoryState,
    nativeX87ReplayOrdinaryState,
    nativeX87ReplaySetConditionMemoryBehavior, initialSymbolic, conditionExact,
    writeOperand8, SymbolicBehavior.write32,
    concreteBehaviorNextMachineState, SymbolicBehavior.eval,
    initialSymbolic, StageA.Formal.applyWrites,
    symbolicRead8,
    StageA.Formal.Expr.eval, BoolExpr.eval,
    Memory.read32]
  rw [addressExact, byteOneExact, byteTwoExact, byteThreeExact]
  apply congrArg (input.memory.write32
    (input.registers.edx + BitVec.ofNat 32 displacement))
  rw [inputFlagConditionalUnitEval input bit]
  exact Memory.setConditionLowByte
    (input.memory
      (input.registers.edx + BitVec.ofNat 32 displacement))
    (input.memory
      (input.registers.edx + BitVec.ofNat 32 displacement +
        BitVec.ofNat 32 1))
    (input.memory
      (input.registers.edx + BitVec.ofNat 32 displacement +
        BitVec.ofNat 32 2))
    (input.memory
      (input.registers.edx + BitVec.ofNat 32 displacement +
        BitVec.ofNat 32 3))
    (input.eflags.extractLsb' bit 1)

private theorem nativeX87ReplaySetConditionMemoryState_memory_below
    (displacement : Nat) (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState .below
      (nativeX87ReplayAddressing (some .edx) displacement) input).memory =
      input.memory.write32
        (input.registers.edx + BitVec.ofNat 32 displacement)
        ((Memory.read32 input.memory
            (input.registers.edx + BitVec.ofNat 32 displacement) &&&
              BitVec.ofNat 32 0xffffff00) |||
          BitVec.ofNat 32 (input.eflags.extractLsb' 0 1).toNat) :=
  nativeX87ReplaySetConditionMemoryState_memory_inputFlag .below 0
    displacement input rfl

private theorem nativeX87ReplaySetConditionMemoryState_memory_parity
    (displacement : Nat) (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState .parity
      (nativeX87ReplayAddressing (some .edx) displacement) input).memory =
      input.memory.write32
        (input.registers.edx + BitVec.ofNat 32 displacement)
        ((Memory.read32 input.memory
            (input.registers.edx + BitVec.ofNat 32 displacement) &&&
              BitVec.ofNat 32 0xffffff00) |||
          BitVec.ofNat 32 (input.eflags.extractLsb' 2 1).toNat) :=
  nativeX87ReplaySetConditionMemoryState_memory_inputFlag .parity 2
    displacement input rfl

private theorem nativeX87ReplaySetConditionMemoryState_memory_equal
    (displacement : Nat) (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState .equal
      (nativeX87ReplayAddressing (some .edx) displacement) input).memory =
      input.memory.write32
        (input.registers.edx + BitVec.ofNat 32 displacement)
        ((Memory.read32 input.memory
            (input.registers.edx + BitVec.ofNat 32 displacement) &&&
              BitVec.ofNat 32 0xffffff00) |||
          BitVec.ofNat 32 (input.eflags.extractLsb' 6 1).toNat) :=
  nativeX87ReplaySetConditionMemoryState_memory_inputFlag .equal 6
    displacement input rfl

private theorem nativeX87ReplaySetConditionMemoryState_memory_sign
    (displacement : Nat) (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState .sign
      (nativeX87ReplayAddressing (some .edx) displacement) input).memory =
      input.memory.write32
        (input.registers.edx + BitVec.ofNat 32 displacement)
        ((Memory.read32 input.memory
            (input.registers.edx + BitVec.ofNat 32 displacement) &&&
              BitVec.ofNat 32 0xffffff00) |||
          BitVec.ofNat 32 (input.eflags.extractLsb' 7 1).toNat) :=
  nativeX87ReplaySetConditionMemoryState_memory_inputFlag .sign 7
    displacement input rfl

private theorem nativeX87ReplaySetConditionMemoryState_memory_overflow
    (displacement : Nat) (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState .overflow
      (nativeX87ReplayAddressing (some .edx) displacement) input).memory =
      input.memory.write32
        (input.registers.edx + BitVec.ofNat 32 displacement)
        ((Memory.read32 input.memory
            (input.registers.edx + BitVec.ofNat 32 displacement) &&&
              BitVec.ofNat 32 0xffffff00) |||
          BitVec.ofNat 32 (input.eflags.extractLsb' 11 1).toNat) :=
  nativeX87ReplaySetConditionMemoryState_memory_inputFlag .overflow 11
    displacement input rfl

@[simp] private theorem nativeX87ReplaySetConditionMemoryState_registers
    (condition : Condition) (destination : Addressing)
    (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState condition destination
      input).registers = input.registers := by
  cases condition <;>
    apply Registers.eq_of_fields <;>
    simp [nativeX87ReplaySetConditionMemoryState,
      nativeX87ReplayOrdinaryState,
      nativeX87ReplaySetConditionMemoryBehavior, conditionExpression,
      writeOperand8, SymbolicBehavior.write32,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      initialSymbolic, Registers.get, StageA.Formal.Expr.eval]

@[simp] private theorem nativeX87ReplaySetConditionMemoryState_eflags
    (condition : Condition) (destination : Addressing)
    (input : MachineState) :
    (nativeX87ReplaySetConditionMemoryState condition destination
      input).eflags = input.eflags := by
  cases condition <;>
    apply nativeX87ReplayOrdinaryState_eflags_of_initialFlags <;>
    simp [nativeX87ReplaySetConditionMemoryBehavior, conditionExpression,
      writeOperand8, SymbolicBehavior.write32, initialSymbolic] <;>
    split <;> rfl

theorem NativeX87ReplayTemplateRole.semanticStep_setConditionMemory
    (rva size undefinedSlot : Nat) (condition : Condition)
    (destination : Addressing) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.setCondition condition (.memory destination)) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplaySetConditionMemoryState condition destination input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · cases condition <;> rfl
  · cases condition <;>
      simp [nativeX87ReplaySetConditionMemoryBehavior, writeOperand8,
        SymbolicBehavior.write32, initialSymbolic]
    all_goals split <;> rfl

def nativeX87ReplayAndRegisterBehavior (undefinedSlot : Nat)
    (destination : Reg) (source : Operand32) : SymbolicBehavior :=
  let left := initialSymbolic.registers.get destination
  let right := readOperand32 initialSymbolic source
  let result := Expr.bitAnd left right
  {
    initialSymbolic with
      registers := initialSymbolic.registers.set destination result
      flags := some (logicalFlags undefinedSlot result)
  }

def nativeX87ReplayAndRegisterState (undefinedSlot : Nat)
    (destination : Reg) (source : Operand32)
    (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayAndRegisterBehavior undefinedSlot destination source) input

@[simp] private theorem nativeX87ReplayAndRegisterState_memory
    (undefinedSlot : Nat) (destination : Reg) (source : Operand32)
    (input : MachineState) :
    (nativeX87ReplayAndRegisterState undefinedSlot destination source
      input).memory = input.memory := by
  rfl

private theorem nativeX87ReplayAndRegisterState_register
    (undefinedSlot : Nat) (destination : Reg) (source : Operand32)
    (input : MachineState) :
    (nativeX87ReplayAndRegisterState undefinedSlot destination source
      input).registers.get destination =
      input.registers.get destination &&&
        (readOperand32 initialSymbolic source).eval input := by
  cases destination <;> cases source <;>
    simp [nativeX87ReplayAndRegisterState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayAndRegisterBehavior, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, readOperand32]

private theorem nativeX87ReplayAndRegisterState_register_other
    (undefinedSlot : Nat) (destination register : Reg) (source : Operand32)
    (input : MachineState) (different : register ≠ destination) :
    (nativeX87ReplayAndRegisterState undefinedSlot destination source
      input).registers.get register = input.registers.get register := by
  cases destination <;> cases register <;>
    simp_all [nativeX87ReplayAndRegisterState,
      nativeX87ReplayOrdinaryState, nativeX87ReplayAndRegisterBehavior,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      initialSymbolic, Registers.set, Registers.get,
      StageA.Formal.Expr.eval]

theorem NativeX87ReplayTemplateRole.semanticStep_andRegister
    (rva size undefinedSlot : Nat) (destination : Reg)
    (source : Operand32) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.binary .and (.register destination) source) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayAndRegisterState undefinedSlot destination source
          input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · rfl

def nativeX87ReplayOrRegisterBehavior (undefinedSlot : Nat)
    (destination : Reg) (source : Operand32) : SymbolicBehavior :=
  let left := initialSymbolic.registers.get destination
  let right := readOperand32 initialSymbolic source
  let result := Expr.bitOr left right
  {
    initialSymbolic with
      registers := initialSymbolic.registers.set destination result
      flags := some (logicalFlags undefinedSlot result)
  }

def nativeX87ReplayOrRegisterState (undefinedSlot : Nat)
    (destination : Reg) (source : Operand32)
    (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState
    (nativeX87ReplayOrRegisterBehavior undefinedSlot destination source) input

@[simp] private theorem nativeX87ReplayOrRegisterState_memory
    (undefinedSlot : Nat) (destination : Reg) (source : Operand32)
    (input : MachineState) :
    (nativeX87ReplayOrRegisterState undefinedSlot destination source
      input).memory = input.memory := by
  rfl

private theorem nativeX87ReplayOrRegisterState_register
    (undefinedSlot : Nat) (destination : Reg) (source : Operand32)
    (input : MachineState) :
    (nativeX87ReplayOrRegisterState undefinedSlot destination source
      input).registers.get destination =
      input.registers.get destination |||
        (readOperand32 initialSymbolic source).eval input := by
  cases destination <;> cases source <;>
    simp [nativeX87ReplayOrRegisterState, nativeX87ReplayOrdinaryState,
      nativeX87ReplayOrRegisterBehavior, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, readOperand32]

private theorem nativeX87ReplayOrRegisterState_register_other
    (undefinedSlot : Nat) (destination register : Reg) (source : Operand32)
    (input : MachineState) (different : register ≠ destination) :
    (nativeX87ReplayOrRegisterState undefinedSlot destination source
      input).registers.get register = input.registers.get register := by
  cases destination <;> cases register <;>
    simp_all [nativeX87ReplayOrRegisterState,
      nativeX87ReplayOrdinaryState, nativeX87ReplayOrRegisterBehavior,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval,
      initialSymbolic, Registers.set, Registers.get,
      StageA.Formal.Expr.eval]

theorem NativeX87ReplayTemplateRole.semanticStep_orRegister
    (rva size undefinedSlot : Nat) (destination : Reg)
    (source : Operand32) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva
        (.binary .or (.register destination) source) size).semanticStep
        pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayOrRegisterState undefinedSlot destination source
          input) := by
  apply NativeX87ReplayTemplateRole.semanticStep_ordinaryNext
  · rfl
  · rfl

def nativeX87ReplayRetBehavior : SymbolicBehavior :=
  let stack := initialSymbolic.registers.esp
  let target := symbolicRead32 initialSymbolic stack
  {
    initialSymbolic with
      registers := initialSymbolic.registers.set .esp (stack.offset 4)
      outcome := some (.returned target)
  }

def nativeX87ReplayRetState (input : MachineState) : MachineState :=
  nativeX87ReplayOrdinaryState nativeX87ReplayRetBehavior input

@[simp] private theorem nativeX87ReplayRetState_memory
    (input : MachineState) :
    (nativeX87ReplayRetState input).memory = input.memory := by
  rfl

theorem NativeX87ReplayTemplateRole.semanticStep_ret
    (rva size undefinedSlot : Nat) (input : MachineState) :
    (NativeX87ReplayTemplateRole.ordinary rva .ret size).semanticStep
        pe imports undefinedSlot input =
      .stopped
        (.returned (Memory.read32 input.memory input.registers.esp))
        (nativeX87ReplayRetState input) := by
  rfl

def nativeX87ReplayFrStorState (restored : StageA.X87.PhysicalState)
    (input : MachineState) : MachineState := {
  input with
    x87 := kernelX87LegacyState restored input.x87.semantics
    x87Physical := restored
}

private theorem nativeX87ReplayMovFromOperandState_x87Physical
    (destination : Reg) (source : Operand32) (input : MachineState) :
    (nativeX87ReplayMovFromOperandState destination source input).x87Physical =
      input.x87Physical :=
  nativeX87ReplayOrdinaryState_x87Physical _ _

private theorem nativeX87ReplayMovFromOperandState_x87Semantics
    (destination : Reg) (source : Operand32) (input : MachineState) :
    (nativeX87ReplayMovFromOperandState destination source input).x87Semantics =
      input.x87Semantics :=
  nativeX87ReplayOrdinaryState_x87Semantics _ _

private theorem nativeX87ReplayMovToMemoryState_x87Semantics
    (destination : Addressing) (source : Reg) (input : MachineState) :
    (nativeX87ReplayMovToMemoryState destination source input).x87Semantics =
      input.x87Semantics :=
  nativeX87ReplayOrdinaryState_x87Semantics _ _

private theorem nativeX87ReplayPushOperandState_x87Physical
    (source : Operand32) (input : MachineState) :
    (nativeX87ReplayPushOperandState source input).x87Physical =
      input.x87Physical :=
  nativeX87ReplayOrdinaryState_x87Physical _ _

private theorem nativeX87ReplayPushOperandState_x87Semantics
    (source : Operand32) (input : MachineState) :
    (nativeX87ReplayPushOperandState source input).x87Semantics =
      input.x87Semantics :=
  nativeX87ReplayOrdinaryState_x87Semantics _ _

private theorem nativeX87ReplayPopRegState_x87Physical
    (destination : Reg) (input : MachineState) :
    (nativeX87ReplayPopRegState destination input).x87Physical =
      input.x87Physical :=
  nativeX87ReplayOrdinaryState_x87Physical _ _

private theorem nativeX87ReplayPopRegState_x87Semantics
    (destination : Reg) (input : MachineState) :
    (nativeX87ReplayPopRegState destination input).x87Semantics =
      input.x87Semantics :=
  nativeX87ReplayOrdinaryState_x87Semantics _ _

private theorem nativeX87ReplayPopFlagsState_x87Physical
    (input : MachineState) :
    (nativeX87ReplayPopFlagsState input).x87Physical = input.x87Physical :=
  nativeX87ReplayOrdinaryState_x87Physical _ _

private theorem nativeX87ReplayPopFlagsState_x87Semantics
    (input : MachineState) :
    (nativeX87ReplayPopFlagsState input).x87Semantics = input.x87Semantics :=
  nativeX87ReplayOrdinaryState_x87Semantics _ _

private theorem nativeX87ReplayFrStorState_x87Physical
    (restored : StageA.X87.PhysicalState) (input : MachineState) :
    (nativeX87ReplayFrStorState restored input).x87Physical = restored :=
  rfl

private theorem nativeX87ReplayFrStorState_x87Semantics
    (restored : StageA.X87.PhysicalState) (input : MachineState) :
    (nativeX87ReplayFrStorState restored input).x87Semantics =
      input.x87Semantics :=
  rfl

@[simp] private theorem nativeX87ReplayFrStorState_eflags
    (restored : StageA.X87.PhysicalState) (input : MachineState) :
    (nativeX87ReplayFrStorState restored input).eflags = input.eflags :=
  rfl

theorem NativeX87ReplayTemplateRole.semanticStep_frStor
    (rva size undefinedSlot : Nat) (addressing : Addressing)
    (input : MachineState) (restored : StageA.X87.PhysicalState)
    (address : Word)
    (addressExact : kernelX87FrameAddress addressing input = address)
    (addressValid : kernelX87FrameAddressValid address = true)
    (encoded :
      StageA.Relational.Engine.readBytes input.memory address
          kernelX87FrameBytes =
        encodeKernelX87Frame restored)
    (representable : KernelX87PhysicalStateRepresentable restored) :
    (NativeX87ReplayTemplateRole.x87Frame rva {
      operation := .frStor
      addressing
      size
    }).semanticStep pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayFrStorState restored input) := by
  unfold NativeX87ReplayTemplateRole.semanticStep executeKernelX87Frame?
  simp only [addressExact, addressValid, Bool.not_true, Bool.false_eq_true]
  rw [encoded, representable]
  rfl

def nativeX87ReplayFnSaveState (address : Word)
    (input : MachineState) : MachineState := {
  input with
    memory := writeX87FrameBytes input.memory address
      (encodeKernelX87Frame input.x87Physical)
    x87 := kernelX87LegacyState StageA.X87.initialPhysicalState
      input.x87.semantics
    x87Physical := StageA.X87.initialPhysicalState
}

@[simp] private theorem nativeX87ReplayFnSaveState_memory
    (address : Word) (input : MachineState) :
    (nativeX87ReplayFnSaveState address input).memory =
      writeX87FrameBytes input.memory address
        (encodeKernelX87Frame input.x87Physical) := by
  rfl

@[simp] private theorem nativeX87ReplayFnSaveState_registers
    (address : Word) (input : MachineState) :
    (nativeX87ReplayFnSaveState address input).registers =
      input.registers := by
  rfl

@[simp] private theorem nativeX87ReplayFnSaveState_eflags
    (address : Word) (input : MachineState) :
    (nativeX87ReplayFnSaveState address input).eflags =
      input.eflags := by
  rfl

theorem NativeX87ReplayTemplateRole.semanticStep_fnSave
    (rva size undefinedSlot : Nat) (addressing : Addressing)
    (input : MachineState) (address : Word)
    (addressExact : kernelX87FrameAddress addressing input = address)
    (addressValid : kernelX87FrameAddressValid address = true) :
    (NativeX87ReplayTemplateRole.x87Frame rva {
      operation := .fnSave
      addressing
      size
    }).semanticStep pe imports undefinedSlot input =
      .running (rva + size) (undefinedSlot + 1)
        (nativeX87ReplayFnSaveState address input) := by
  unfold NativeX87ReplayTemplateRole.semanticStep executeKernelX87Frame?
  simp only [addressExact, addressValid, Bool.not_true, Bool.false_eq_true]
  rfl

def runNativeX87ReplayTemplateRoles (pe : PE32) (imports : List PEImport) :
    Nat -> MachineState -> List NativeX87ReplayTemplateRole ->
      PE32InstructionExecution
  | undefinedSlot, state, [] => .running 0 undefinedSlot state
  | undefinedSlot, state, [role] => role.semanticStep pe imports undefinedSlot state
  | undefinedSlot, state, role :: next :: tail =>
      match role.semanticStep pe imports undefinedSlot state with
      | .running nextRva nextSlot nextState =>
          if nextRva == next.rva then
            runNativeX87ReplayTemplateRoles pe imports nextSlot nextState
              (next :: tail)
          else .fault
      | .stopped outcome nextState => .stopped outcome nextState
      | .fault => .fault

private theorem runNativeX87ReplayTemplateRoles_cons_running
    {role next : NativeX87ReplayTemplateRole}
    {tail : List NativeX87ReplayTemplateRole}
    {undefinedSlot nextRva nextSlot : Nat}
    {input nextState : MachineState}
    (executed :
      role.semanticStep pe imports undefinedSlot input =
        .running nextRva nextSlot nextState)
    (linked : nextRva = next.rva) :
    runNativeX87ReplayTemplateRoles pe imports undefinedSlot input
        (role :: next :: tail) =
      runNativeX87ReplayTemplateRoles pe imports nextSlot nextState
        (next :: tail) := by
  simp [runNativeX87ReplayTemplateRoles, executed, linked]

private def nativeX87ReplayNopEndpointRva (rva count : Nat) : Nat :=
  if count = 0 then 0 else rva + count

private def nativeX87ReplayNopState : Nat -> MachineState -> MachineState
  | 0, input => input
  | count + 1, input =>
      nativeX87ReplayNopState count
        (nativeX87ReplayOrdinaryState initialSymbolic input)

@[simp] private theorem nativeX87ReplayNopState_registers
    (count : Nat) (input : MachineState) :
    (nativeX87ReplayNopState count input).registers = input.registers := by
  induction count generalizing input with
  | zero => rfl
  | succ count induction =>
      simp only [nativeX87ReplayNopState, induction]
      apply Registers.eq_of_fields <;>
        simp [nativeX87ReplayOrdinaryState,
          concreteBehaviorNextMachineState, SymbolicBehavior.eval,
          initialSymbolic, Registers.get, StageA.Formal.Expr.eval]

@[simp] private theorem nativeX87ReplayNopState_memory
    (count : Nat) (input : MachineState) :
    (nativeX87ReplayNopState count input).memory = input.memory := by
  induction count generalizing input with
  | zero => rfl
  | succ count induction =>
      simp only [nativeX87ReplayNopState, induction]
      rfl

@[simp] private theorem nativeX87ReplayNopState_eflags
    (count : Nat) (input : MachineState) :
    (nativeX87ReplayNopState count input).eflags = input.eflags := by
  induction count generalizing input with
  | zero => rfl
  | succ count induction =>
      simp only [nativeX87ReplayNopState, induction]
      exact nativeX87ReplayOrdinaryState_eflags_of_initialFlags
        initialSymbolic input rfl rfl

@[simp] private theorem nativeX87ReplayNopRoles_length
    (rva count : Nat) :
    (nativeX87ReplayNopRoles rva count).length = count := by
  induction count generalizing rva with
  | zero => rfl
  | succ count induction =>
      simp [nativeX87ReplayNopRoles, induction]

private theorem nativeX87ReplayNopRoles_running
    (rva count undefinedSlot : Nat) (input : MachineState) :
    runNativeX87ReplayTemplateRoles pe imports undefinedSlot input
        (nativeX87ReplayNopRoles rva count) =
      .running (nativeX87ReplayNopEndpointRva rva count)
        (undefinedSlot + count) (nativeX87ReplayNopState count input) := by
  induction count generalizing rva undefinedSlot input with
  | zero =>
      simp [nativeX87ReplayNopRoles, runNativeX87ReplayTemplateRoles,
        nativeX87ReplayNopEndpointRva, nativeX87ReplayNopState]
  | succ count induction =>
      cases count with
      | zero =>
          simp [nativeX87ReplayNopRoles, runNativeX87ReplayTemplateRoles,
            NativeX87ReplayTemplateRole.semanticStep_nop,
            nativeX87ReplayNopEndpointRva, nativeX87ReplayNopState]
      | succ tail =>
          change runNativeX87ReplayTemplateRoles pe imports undefinedSlot input
              (.ordinary rva .nop 1 ::
                .ordinary (rva + 1) .nop 1 ::
                  nativeX87ReplayNopRoles (rva + 1 + 1) tail) =
            _
          rw [runNativeX87ReplayTemplateRoles_cons_running
            (NativeX87ReplayTemplateRole.semanticStep_nop
              (pe := pe) (imports := imports)
              rva 1 undefinedSlot input)
            (by simp [NativeX87ReplayTemplateRole.rva])]
          change runNativeX87ReplayTemplateRoles pe imports
              (undefinedSlot + 1)
              (nativeX87ReplayOrdinaryState initialSymbolic input)
              (nativeX87ReplayNopRoles (rva + 1) (tail + 1)) =
            _
          rw [induction (rva := rva + 1)
            (undefinedSlot := undefinedSlot + 1)]
          simp [nativeX87ReplayNopEndpointRva, nativeX87ReplayNopState,
            Nat.add_assoc]
          omega

theorem CheckedKernelMixedReplayInstruction.semanticStep_role
    (entry : CheckedKernelMixedReplayInstruction pe imports)
    (role : NativeX87ReplayTemplateRole)
    (roleExact : kernelMixedReplayTemplateRole? pe entry = some role)
    (undefinedSlot : Nat) (input : MachineState) :
    entry.instruction.semanticStep pe imports undefinedSlot input =
      role.semanticStep pe imports undefinedSlot input := by
  rcases entry with ⟨instruction, checked⟩
  cases instruction with
  | ordinary instruction =>
      have checkedParts := checked
      simp only [KernelMixedReplayInstruction.checked, Bool.and_eq_true]
        at checkedParts
      rcases checkedParts with ⟨_ordinaryChecked, specializedDecodersClear⟩
      cases decodedExact : instruction.decode? pe with
      | none =>
          simp [kernelMixedReplayTemplateRole?, decodedExact] at roleExact
      | some decoded =>
          simp [kernelMixedReplayTemplateRole?, decodedExact] at roleExact
          subst role
          change (KernelMixedReplayInstruction.ordinary instruction).semanticStep
              pe imports undefinedSlot input = _
          rw [ExactKernelMixedReplayStaticStep.ordinary_semanticStep instruction
            specializedDecodersClear decoded decodedExact]
          cases decoded
          rfl
  | x87Frame instruction =>
      cases decodedExact : instruction.decode? pe with
      | none =>
          simp [kernelMixedReplayTemplateRole?, decodedExact] at roleExact
      | some decoded =>
          simp [kernelMixedReplayTemplateRole?, decodedExact] at roleExact
          subst role
          change (KernelMixedReplayInstruction.x87Frame instruction).semanticStep
              pe imports undefinedSlot input = _
          rw [ExactKernelMixedReplayStaticStep.x87Frame_semanticStep instruction
            decoded decodedExact]
          rfl
  | x87Command instruction =>
      have checkedParts := checked
      simp only [KernelMixedReplayInstruction.checked, Bool.and_eq_true]
        at checkedParts
      rcases checkedParts with ⟨_commandChecked, frameDecoderClear⟩
      cases decodedExact : instruction.decode? pe with
      | none =>
          simp [kernelMixedReplayTemplateRole?, decodedExact] at roleExact
      | some decoded =>
          simp [kernelMixedReplayTemplateRole?, decodedExact] at roleExact
          subst role
          change (KernelMixedReplayInstruction.x87Command instruction).semanticStep
              pe imports undefinedSlot input = _
          rw [ExactKernelMixedReplayStaticStep.x87Command_semanticStep instruction
            frameDecoderClear decoded decodedExact]
          rfl

theorem CheckedKernelMixedReplayInstruction.role_rva
    (entry : CheckedKernelMixedReplayInstruction pe imports)
    (role : NativeX87ReplayTemplateRole)
    (roleExact : kernelMixedReplayTemplateRole? pe entry = some role) :
    role.rva = entry.instruction.rva := by
  rcases entry with ⟨instruction, checked⟩
  cases instruction with
  | ordinary instruction =>
      change role.rva = instruction.rva
      simp only [kernelMixedReplayTemplateRole?] at roleExact
      simp only [Option.bind_eq_bind] at roleExact
      rw [Option.bind_eq_some_iff] at roleExact
      obtain ⟨decoded, _decodedExact, roleExact⟩ := roleExact
      have roleValueExact := Option.some.inj roleExact
      simpa [NativeX87ReplayTemplateRole.rva] using
        congrArg NativeX87ReplayTemplateRole.rva roleValueExact.symm
  | x87Frame instruction =>
      change role.rva = instruction.rva
      simp only [kernelMixedReplayTemplateRole?] at roleExact
      simp only [Option.bind_eq_bind] at roleExact
      rw [Option.bind_eq_some_iff] at roleExact
      obtain ⟨decoded, _decodedExact, roleExact⟩ := roleExact
      have roleValueExact := Option.some.inj roleExact
      simpa [NativeX87ReplayTemplateRole.rva] using
        congrArg NativeX87ReplayTemplateRole.rva roleValueExact.symm
  | x87Command instruction =>
      change role.rva = instruction.rva
      simp only [kernelMixedReplayTemplateRole?] at roleExact
      simp only [Option.bind_eq_bind] at roleExact
      rw [Option.bind_eq_some_iff] at roleExact
      obtain ⟨decoded, _decodedExact, roleExact⟩ := roleExact
      have roleValueExact := Option.some.inj roleExact
      simpa [NativeX87ReplayTemplateRole.rva] using
        congrArg NativeX87ReplayTemplateRole.rva roleValueExact.symm

theorem kernelMixedReplayTemplateRoles?_cons_eq_some
    (entry : CheckedKernelMixedReplayInstruction pe imports)
    (tail : List (CheckedKernelMixedReplayInstruction pe imports))
    (roles : List NativeX87ReplayTemplateRole)
    (exact :
      kernelMixedReplayTemplateRoles? pe (entry :: tail) = some roles) :
    ∃ role tailRoles,
      kernelMixedReplayTemplateRole? pe entry = some role ∧
      kernelMixedReplayTemplateRoles? pe tail = some tailRoles ∧
      roles = role :: tailRoles := by
  unfold kernelMixedReplayTemplateRoles? at exact ⊢
  simp only [List.mapM_cons, Option.bind_eq_bind] at exact
  rw [Option.bind_eq_some_iff] at exact
  obtain ⟨role, roleExact, exact⟩ := exact
  rw [Option.bind_eq_some_iff] at exact
  obtain ⟨tailRoles, tailExact, exact⟩ := exact
  injection exact with rolesExact
  exact ⟨role, tailRoles, roleExact, tailExact, rolesExact.symm⟩

theorem runKernelMixedReplaySemantic_eq_templateRoles
    (entries : List (CheckedKernelMixedReplayInstruction pe imports))
    (roles : List NativeX87ReplayTemplateRole)
    (rolesExact : kernelMixedReplayTemplateRoles? pe entries = some roles) :
    ∀ undefinedSlot input,
      runKernelMixedReplaySemantic pe imports undefinedSlot input
          (checkedKernelMixedReplayInstructions entries) =
        runNativeX87ReplayTemplateRoles pe imports undefinedSlot input roles := by
  induction entries generalizing roles with
  | nil =>
      intro undefinedSlot input
      simp [kernelMixedReplayTemplateRoles?,
        checkedKernelMixedReplayInstructions] at rolesExact
      subst roles
      rfl
  | cons entry tail induction =>
      unfold kernelMixedReplayTemplateRoles? at rolesExact
      simp only [List.mapM_cons, Option.bind_eq_bind] at rolesExact
      rw [Option.bind_eq_some_iff] at rolesExact
      obtain ⟨role, roleExact, rolesExact⟩ := rolesExact
      rw [Option.bind_eq_some_iff] at rolesExact
      obtain ⟨tailRoles, tailRolesExact, rolesExact⟩ := rolesExact
      injection rolesExact
      subst roles
      intro undefinedSlot input
      cases tail with
      | nil =>
          simp [kernelMixedReplayTemplateRoles?] at tailRolesExact
          subst tailRoles
          simp only [checkedKernelMixedReplayInstructions, List.map_cons,
            List.map_nil, runKernelMixedReplaySemantic,
            runNativeX87ReplayTemplateRoles]
          exact CheckedKernelMixedReplayInstruction.semanticStep_role
            entry role roleExact undefinedSlot input
      | cons next rest =>
          obtain ⟨nextRole, roleRest, nextRoleExact, roleRestExact,
              tailRolesShape⟩ :=
            kernelMixedReplayTemplateRoles?_cons_eq_some next rest tailRoles
              tailRolesExact
          subst tailRoles
          have nextRvaExact : nextRole.rva = next.instruction.rva :=
            CheckedKernelMixedReplayInstruction.role_rva
              next nextRole nextRoleExact
          simp only [checkedKernelMixedReplayInstructions, List.map_cons,
            runKernelMixedReplaySemantic, runNativeX87ReplayTemplateRoles]
          rw [CheckedKernelMixedReplayInstruction.semanticStep_role
            entry role roleExact]
          cases first :
              role.semanticStep pe imports undefinedSlot input with
          | running nextRva nextSlot nextState =>
              simp only [first, nextRvaExact]
              split
              · exact induction (nextRole :: roleRest) tailRolesExact
                  nextSlot nextState
              · rfl
          | stopped outcome nextState => rfl
          | fault => rfl

/-- A successful physical x87 command consumes exactly one undefined-value
slot, just like every ordinary and frame instruction in the mixed kernel. -/
theorem executeKernelX87Command?_running_slot
    (pe : PE32) (rva undefinedSlot nextRva nextSlot : Nat)
    (state after : MachineState)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (executed : executeKernelX87Command? pe rva undefinedSlot state descriptor =
      some (.running nextRva nextSlot after)) :
    nextSlot = undefinedSlot + 1 := by
  unfold executeKernelX87Command? at executed
  simp only [Option.bind_eq_bind] at executed
  split at executed <;> try contradiction
  split at executed <;> try contradiction
  split at executed <;> try contradiction
  split at executed <;> try contradiction
  all_goals
    rw [Option.bind_eq_some_iff] at executed
    obtain ⟨memoryAddress, _memoryAddressExact, executed⟩ := executed
    simp only [Option.some.injEq,
      PE32InstructionExecution.running.injEq] at executed
    rcases executed with ⟨_nextRva, nextSlotExact, _afterExact⟩
    exact nextSlotExact.symm

/-- Every successful mixed replay instruction consumes exactly one undefined
value slot.  This is independent of the instruction family and is needed when
phase certificates compose exact native-world states. -/
theorem KernelMixedReplayInstruction.semanticStep_running_slot
    (instruction : KernelMixedReplayInstruction)
    (undefinedSlot nextRva nextSlot : Nat)
    (input after : MachineState)
    (executed : instruction.semanticStep pe imports undefinedSlot input =
      .running nextRva nextSlot after) :
    nextSlot = undefinedSlot + 1 := by
  cases instruction with
  | ordinary instruction =>
      simp only [KernelMixedReplayInstruction.semanticStep] at executed
      unfold StageA.Relational.SymbolicSoundness.KernelInstruction.semanticStep
        at executed
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at executed
      | some decoded =>
          cases resultExact :
              executeInstruction pe imports instruction.rva undefinedSlot
                decoded initialSymbolic with
          | none => simp [decodedExact, resultExact] at executed
          | some result =>
              cases result with
              | next symbolic =>
                  simp only [decodedExact, resultExact,
                    StageA.Relational.SymbolicSoundness.executeInstructionResult]
                    at executed
                  split at executed <;> try contradiction
                  injection executed with _nextRva slotExact _afterExact
                  exact slotExact.symm
              | stop symbolic =>
                  simp only [decodedExact, resultExact,
                    StageA.Relational.SymbolicSoundness.executeInstructionResult]
                    at executed
                  split at executed <;> contradiction
  | x87Frame instruction =>
      simp only [KernelMixedReplayInstruction.semanticStep] at executed
      split at executed <;> try contradiction
      split at executed <;> try contradiction
      injection executed with _nextRva slotExact _afterExact
      exact slotExact.symm
  | x87Command instruction =>
      simp only [KernelMixedReplayInstruction.semanticStep] at executed
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at executed
      | some descriptor =>
          cases commandExact : executeKernelX87Command? pe instruction.rva
              undefinedSlot input descriptor with
          | none => simp [decodedExact, commandExact] at executed
          | some commandResult =>
              simp only [decodedExact, commandExact] at executed
              apply executeKernelX87Command?_running_slot pe instruction.rva
                undefinedSlot nextRva nextSlot input after descriptor
              rw [commandExact]
              exact congrArg some executed

/-- A successful nonempty mixed replay phase threads the slot counter through
all checked instructions; it cannot return to its initial slot silently. -/
theorem runKernelMixedReplaySemantic_running_slot
    (instructions : List KernelMixedReplayInstruction) :
    ∀ undefinedSlot input nextRva nextSlot after,
      runKernelMixedReplaySemantic pe imports undefinedSlot input instructions =
          .running nextRva nextSlot after ->
        nextSlot = undefinedSlot + instructions.length := by
  induction instructions with
  | nil =>
      intro undefinedSlot input nextRva nextSlot after executed
      simp only [runKernelMixedReplaySemantic] at executed
      injection executed with _nextRva slotExact _afterExact
      simpa only [List.length_nil, Nat.add_zero] using slotExact.symm
  | cons instruction tail induction =>
      intro undefinedSlot input nextRva nextSlot after executed
      cases tail with
      | nil =>
          simp only [runKernelMixedReplaySemantic] at executed
          have slot := KernelMixedReplayInstruction.semanticStep_running_slot
            instruction
            undefinedSlot nextRva nextSlot input after executed
          simpa using slot
      | cons next rest =>
          simp only [runKernelMixedReplaySemantic] at executed
          cases first :
              instruction.semanticStep pe imports undefinedSlot input with
          | running firstRva firstSlot firstAfter =>
              simp only [first] at executed
              split at executed <;> try contradiction
              have firstSlotExact :=
                KernelMixedReplayInstruction.semanticStep_running_slot
                  instruction
                undefinedSlot firstRva firstSlot input firstAfter first
              have tailSlotExact := induction firstSlot firstAfter nextRva
                nextSlot after executed
              simp only [List.length_cons] at tailSlotExact ⊢
              omega
          | stopped outcome state => simp [first] at executed
          | fault => simp [first] at executed

/-- Retain the operational environment of a nested program while fixing every
static field used by the checked x87 replay inventory. -/
def bindExactNativeX87ReplayNestedProgram
    (_inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (carrier : ExactNestedNativeWorldProgram) :
    ExactNestedNativeWorldProgram := {
  pe
  imports
  environment := carrier.environment
  callableExternal := carrier.callableExternal
  indirectTargets := table.nativeTargetInventory
  callbackTargetRvas := carrier.callbackTargetRvas
  protocolAction := carrier.protocolAction
}

@[simp] theorem bindExactNativeX87ReplayNestedProgram_pe
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (carrier : ExactNestedNativeWorldProgram) :
    (bindExactNativeX87ReplayNestedProgram inventory carrier).pe = pe :=
  rfl

@[simp] theorem bindExactNativeX87ReplayNestedProgram_imports
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (carrier : ExactNestedNativeWorldProgram) :
    (bindExactNativeX87ReplayNestedProgram inventory carrier).imports = imports :=
  rfl

theorem nativeX87ReplayBridgeTargetInventory_exact
    (table : NativeX87ReplayBridgeTable) :
    table.nativeTargetInventory.targetSet?
        table.callInstruction.rva .call =
      some table.nativeTargetSet := by
  simp [NativeX87ReplayBridgeTable.nativeTargetInventory,
    NativeIndirectTargetInventory.targetSet?,
    NativeX87ReplayBridgeTable.nativeTargetSet]

@[simp] theorem bindExactNativeX87ReplayNestedProgram_targetInventory
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (carrier : ExactNestedNativeWorldProgram) :
    (bindExactNativeX87ReplayNestedProgram inventory carrier).indirectTargets.targetSet?
        table.callInstruction.rva .call =
      some table.nativeTargetSet :=
  nativeX87ReplayBridgeTargetInventory_exact table

/-- The structural binding for `bindExactNativeX87ReplayNestedProgram` is
theorem-derived and does not consume any dynamic bridge authority. -/
def exactNativeX87ReplayKernelProgramBinding
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (carrier : ExactNestedNativeWorldProgram)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    ExactNativeX87ReplayKernelProgramBinding inventory
      (bindExactNativeX87ReplayNestedProgram inventory carrier) := {
  peExact := rfl
  importsExact := rfl
  imageBounded
  targetInventory :=
    bindExactNativeX87ReplayNestedProgram_targetInventory inventory carrier
}

/-- The fixed replay call boundary is an exact internal native call.  Its
decoder class, finite target resolution, return frame, and successor machine
state all come from checked PE semantics; no runtime target assertion is
accepted from generated data. -/
theorem exactNativeX87ReplayCallStep
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32} {caller logicalInput : MachineState}
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    program.transitionSystem.step
        (.running table.callInstruction.rva 0 caller [] 0 []
          RelationalWorld.empty []) = {
      next := .running runtimeTarget.target.descriptor.bridge.entry.rva 0
        (indirectCallEntryState
          (program.pe.imageBase + table.continuationRva) caller)
        [{ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) }]
        0 [] RelationalWorld.empty []
      observation := none
    } := by
  have shapeChecked := runtimeTarget.target.static.shapeChecked
  have callChecked := table.callSiteChecked pe imports relocations shapeChecked
  have decodersClear :=
    table.callSpecializedDecodersClear pe imports relocations shapeChecked
  have callStepExact :
      stepKernelPE32Instruction pe imports
          (.running table.callInstruction.rva 0 caller) =
        .stopped
          (.indirectCall (table.callSite.targetWord caller)
            table.continuationRva
            (pe.imageBase + table.continuationRva))
          (indirectCallEntryState
            (pe.imageBase + table.continuationRva) caller) := by
    simpa [NativeX87ReplayBridgeTable.callSite] using
      table.callSite.step_exactIndirectCallState pe imports 0 caller callChecked
        decodersClear
  have targetResolved := table.resolveDescriptorTarget pe imports relocations
    runtimeTarget.target.descriptor shapeChecked
    runtimeTarget.target.descriptorMember
  have programTargetResolved :
      program.indirectTargets.resolve? pe RelationalWorld.empty
          table.callInstruction.rva .call
          (runtimeTarget.target.descriptor.bridge.address pe) =
        some (.internalRva
          runtimeTarget.target.descriptor.bridge.entry.rva) := by
    unfold NativeIndirectTargetInventory.resolve? at targetResolved ⊢
    rw [programBinding.targetInventory]
    rw [nativeX87ReplayBridgeTargetInventory_exact table] at targetResolved
    exact targetResolved
  simp [ExactNestedNativeWorldProgram.transitionSystem,
    stepPE32NestedNativeWorldExecution, programBinding.peExact,
    programBinding.importsExact, callStepExact,
    transitionFromNestedNativeWorldOutcome, source.callTarget,
    programTargetResolved]

structure ExactNativeX87ReplaySilentRunningEndpoint
    (result : NestedNativeWorldExecution × List WorldRelationalObservable)
    (expectedRva expectedSlot : Nat)
    (expectedCalls : List NativeCallFrame) where
  state : MachineState
  exact : result =
    (.running expectedRva expectedSlot state expectedCalls 0 []
      RelationalWorld.empty [], [])

/-- Inspect one computed segment without accepting a submitted endpoint.  The
fixed-template executor deliberately runs in the empty nested-world envelope;
any call/event/world/callback drift or non-silent observation fails closed. -/
def exactNativeX87ReplaySilentRunningEndpoint?
    (result : NestedNativeWorldExecution × List WorldRelationalObservable)
    (expectedRva expectedSlot : Nat)
    (expectedCalls : List NativeCallFrame) :
    Option (ExactNativeX87ReplaySilentRunningEndpoint
      result expectedRva expectedSlot expectedCalls) :=
  match result with
  | (.running rva undefinedSlot state calls eventIndex events world
        externalFrames, observations) =>
      if exact : rva = expectedRva ∧ undefinedSlot = expectedSlot ∧
          calls = expectedCalls ∧ eventIndex = 0 ∧ events = [] ∧
          world = RelationalWorld.empty ∧ externalFrames = [] ∧
          observations = [] then
        some {
          state
          exact := by
            rcases exact with ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
            rfl
        }
      else none
  | _ => none

/-- The state stored by a checked silent endpoint is uniquely determined by
an exact run equation. -/
theorem ExactNativeX87ReplaySilentRunningEndpoint.state_eq_of_run
    {result : NestedNativeWorldExecution × List WorldRelationalObservable}
    {expectedRva expectedSlot : Nat}
    {expectedCalls : List NativeCallFrame}
    (endpoint : ExactNativeX87ReplaySilentRunningEndpoint
      result expectedRva expectedSlot expectedCalls)
    (after : MachineState)
    (runExact : result =
      (.running expectedRva expectedSlot after expectedCalls 0 []
        RelationalWorld.empty [], [])) :
    endpoint.state = after := by
  have equal := endpoint.exact.symm.trans runExact
  have runningEqual := congrArg Prod.fst equal
  injection runningEqual

/-- Package one exact silent run as its checked endpoint. -/
def ExactNativeX87ReplaySilentRunningEndpoint.ofRun
    {result : NestedNativeWorldExecution × List WorldRelationalObservable}
    {expectedRva expectedSlot : Nat}
    {expectedCalls : List NativeCallFrame}
    (after : MachineState)
    (runExact : result =
      (.running expectedRva expectedSlot after expectedCalls 0 []
        RelationalWorld.empty [], [])) :
    ExactNativeX87ReplaySilentRunningEndpoint
      result expectedRva expectedSlot expectedCalls := {
  state := after
  exact := runExact
}

/-- Exact runs reduce the endpoint checker to the canonical endpoint value.
This equality lets dependent certificate construction reuse the checked state
definitionally instead of recovering it from an existential `isSome` fact. -/
theorem exactNativeX87ReplaySilentRunningEndpoint_eq_some_of_run
    {result : NestedNativeWorldExecution × List WorldRelationalObservable}
    {expectedRva expectedSlot : Nat}
    {expectedCalls : List NativeCallFrame}
    (after : MachineState)
    (runExact : result =
      (.running expectedRva expectedSlot after expectedCalls 0 []
        RelationalWorld.empty [], [])) :
    exactNativeX87ReplaySilentRunningEndpoint?
        result expectedRva expectedSlot expectedCalls =
      some (ExactNativeX87ReplaySilentRunningEndpoint.ofRun after runExact) := by
  subst result
  simp [exactNativeX87ReplaySilentRunningEndpoint?,
    ExactNativeX87ReplaySilentRunningEndpoint.ofRun]

/-- Lift one checked fixed-template role list to an exact nested-world run.
Decoding and symbolic interpretation are consumed through the static checked
entries; the only phase-specific proof is the concrete role replay equation.
Endpoint checking and later composition reuse this opaque result without
replaying the region semantics. -/
theorem exactNativeX87ReplayPhaseRun_of_roles
    (program : ExactNestedNativeWorldProgram)
    (entries : List
      (CheckedKernelMixedReplayInstruction program.pe program.imports))
    (first : CheckedKernelMixedReplayInstruction program.pe program.imports)
    (tail : List
      (CheckedKernelMixedReplayInstruction program.pe program.imports))
    (entriesExact : entries = first :: tail)
    (roles : List NativeX87ReplayTemplateRole)
    (rolesExact :
      kernelMixedReplayTemplateRoles? program.pe entries = some roles)
    (undefinedSlot finalSlot finalRva : Nat)
    (input after : MachineState)
    (calls : List NativeCallFrame)
    (executed :
      runNativeX87ReplayTemplateRoles program.pe program.imports
          undefinedSlot input roles =
        .running finalRva finalSlot after) :
    runRelatedSteps program.transitionSystem entries.length
        (.running first.instruction.rva undefinedSlot input calls 0 []
          RelationalWorld.empty []) =
      (.running finalRva finalSlot after calls 0 [] RelationalWorld.empty [],
        []) := by
  have semanticExact :=
    runKernelMixedReplaySemantic_eq_templateRoles entries roles rolesExact
      undefinedSlot input
  have concreteExact :=
    runKernelMixedReplayConcrete_composes program.pe program.imports
      (checkedKernelMixedReplayInstructions entries)
      (checkedKernelMixedReplayInstructions_exact entries)
      undefinedSlot input
  have concreteExecuted :
      runKernelMixedReplayConcrete program.pe program.imports undefinedSlot input
          (checkedKernelMixedReplayInstructions entries) =
        .running finalRva finalSlot after := by
    rw [concreteExact, semanticExact, executed]
  subst entries
  have worldExecuted := runRelatedSteps_mixedReplay_running program
    first.instruction (tail.map (·.instruction)) undefinedSlot finalSlot input
    after finalRva calls 0 [] RelationalWorld.empty [] (by
      simpa [checkedKernelMixedReplayInstructions] using concreteExecuted)
  simpa using worldExecuted

/-- Check the endpoint of one exact fixed-template phase without replaying its
decoded semantics. -/
theorem exactNativeX87ReplayPhaseEndpoint_isSome_of_roles
    (program : ExactNestedNativeWorldProgram)
    (entries : List
      (CheckedKernelMixedReplayInstruction program.pe program.imports))
    (first : CheckedKernelMixedReplayInstruction program.pe program.imports)
    (tail : List
      (CheckedKernelMixedReplayInstruction program.pe program.imports))
    (entriesExact : entries = first :: tail)
    (roles : List NativeX87ReplayTemplateRole)
    (rolesExact :
      kernelMixedReplayTemplateRoles? program.pe entries = some roles)
    (undefinedSlot finalSlot finalRva : Nat)
    (input after : MachineState)
    (calls : List NativeCallFrame)
    (executed :
      runNativeX87ReplayTemplateRoles program.pe program.imports
          undefinedSlot input roles =
        .running finalRva finalSlot after) :
    (exactNativeX87ReplaySilentRunningEndpoint?
      (runRelatedSteps program.transitionSystem entries.length
        (.running first.instruction.rva undefinedSlot input calls 0 []
          RelationalWorld.empty []))
      finalRva finalSlot calls).isSome = true := by
  rw [exactNativeX87ReplayPhaseRun_of_roles program entries first tail
    entriesExact roles rolesExact undefinedSlot finalSlot finalRva input after
    calls executed]
  simp [exactNativeX87ReplaySilentRunningEndpoint?]

/-- The fixed replay call reaches the exact bridge entry state.  The indirect
target resolver is checked once here and later endpoint/certificate proofs
reuse this opaque run equation. -/
theorem exactNativeX87ReplayCallRun
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32} {caller logicalInput : MachineState}
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    runRelatedSteps program.transitionSystem 1
        (.running table.callInstruction.rva 0 caller [] 0 []
          RelationalWorld.empty []) =
      (.running runtimeTarget.target.descriptor.bridge.entry.rva 0
        (indirectCallEntryState
          (program.pe.imageBase + table.continuationRva) caller)
        [{ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) }]
        0 [] RelationalWorld.empty [], []) := by
  have callStep := exactNativeX87ReplayCallStep programBinding source
  simpa only [runRelatedSteps, Option.toList_none, List.nil_append] using
    congrArg (fun transition =>
      (transition.next, transition.observation.toList ++ [])) callStep

/-- The fixed replay call always satisfies the canonical silent-endpoint
checker.  Downstream bridge proofs consume this opaque fact instead of
re-running the call decoder and indirect-target resolver. -/
theorem exactNativeX87ReplayCallEndpoint_isSome
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32} {caller logicalInput : MachineState}
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    (exactNativeX87ReplaySilentRunningEndpoint?
      (runRelatedSteps program.transitionSystem 1
        (.running table.callInstruction.rva 0 caller [] 0 []
          RelationalWorld.empty []))
      runtimeTarget.target.descriptor.bridge.entry.rva
      0
      [{ continuationRva := table.continuationRva,
         returnAddress := BitVec.ofNat 32
           (program.pe.imageBase + table.continuationRva) }]).isSome = true := by
  rw [exactNativeX87ReplayCallRun programBinding source]
  simp [exactNativeX87ReplaySilentRunningEndpoint?]

structure ExactNativeX87ReplayCheckedPostFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (returned : MachineState) (result candidateResult : StepResult) : Type where
  targetAfter : runtimeTarget.target.descriptor.bridgeCell.Holds pe
    runtimeTarget.target.descriptor.bridge returned
  activeAfter : Memory.read32 returned.memory
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
  faultFree : result.faults = [] ∧ candidateResult.faults = []
  nonX87Output :
    nativeX87ReplayNonX87OutputChecked
      source.toNativeX87ReplayBridgeSourceFrameEvidence returned
      result.state = true
  memoryEffects :
    nativeX87ReplayMemoryEffectsRelated runtimeTarget.addressMap
      result.memoryEffects candidateResult.memoryEffects = true
  physicalState :
    nativeX87ReplayPhysicalStatesRelatedChecked runtimeTarget.addressMap
      result.state.x87Physical candidateResult.state.x87Physical = true
  outputEncoded : StageA.Relational.Engine.readBytes returned.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
      kernelX87FrameBytes =
    encodeKernelX87Frame candidateResult.state.x87Physical

/-- Check every post-frame equality against the endpoint computed by the exact
candidate transition system. -/
def exactNativeX87ReplayCheckedPostFrame?
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (returned : MachineState) (result candidateResult : StepResult) :
    Option (ExactNativeX87ReplayCheckedPostFrame runtimeTarget source returned
      result candidateResult) :=
  if targetAfter : Memory.read32 returned.memory
      (runtimeTarget.target.descriptor.bridgeCell.address pe) =
        runtimeTarget.target.descriptor.bridge.address pe then
    if activeAfter : Memory.read32 returned.memory
        (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) =
          source.frameAddress then
      if parentAfter : Memory.read32 returned.memory
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) =
            source.parentAddress then
        if privateStackEstablished : Memory.read32 returned.memory
            (source.frameAddress +
              BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
              BitVec.ofNat 32 0 then
          if statusSucceeded : Memory.read32 returned.memory
              (source.frameAddress +
                BitVec.ofNat 32 nativeX87FrameStatusOffset) =
                BitVec.ofNat 32 0 then
            if faultFree :
                result.faults = [] ∧ candidateResult.faults = [] then
              if nonX87Output :
                  nativeX87ReplayNonX87OutputChecked
                    source.toNativeX87ReplayBridgeSourceFrameEvidence returned
                    result.state = true then
                if memoryEffects :
                    nativeX87ReplayMemoryEffectsRelated runtimeTarget.addressMap
                      result.memoryEffects candidateResult.memoryEffects = true then
                  if physicalState :
                      nativeX87ReplayPhysicalStatesRelatedChecked
                        runtimeTarget.addressMap result.state.x87Physical
                        candidateResult.state.x87Physical = true then
                    if outputEncoded :
                        StageA.Relational.Engine.readBytes returned.memory
                          (source.frameAddress +
                            BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
                          kernelX87FrameBytes =
                            encodeKernelX87Frame
                              candidateResult.state.x87Physical then
                      some {
                        targetAfter := ⟨rfl, targetAfter⟩
                        activeAfter
                        parentAfter
                        privateStackEstablished
                        statusSucceeded
                        faultFree
                        nonX87Output
                        memoryEffects
                        physicalState
                        outputEncoded
                      }
                    else none
                  else none
                else none
              else none
            else none
          else none
        else none
      else none
    else none
  else none

/-- Exact semantic equations for the universal fixed bridge template at one
checked runtime target and admitted source frame. -/
structure ExactNativeX87ReplayFixedTemplateCertificate
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) where
  result : StepResult
  candidateResult : StepResult
  calleeEntry : MachineState
  instructionSlot : Nat
  instructionEntryState : MachineState
  originalExecuted : executeX87Singleton originalPe
    (replayInstructionRecord runtimeTarget.target.descriptor.replay)
    logicalInput = some result
  candidateExecuted : executeX87Singleton pe
    (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
      runtimeTarget.addressMap.candidateInstructionRva)
    instructionEntryState = some candidateResult
  instructionPhysicalInput :
    instructionEntryState.x87Physical = source.candidateInput.x87Physical
  instructionCommandInput :
    StageA.Relational.X87.commandStepInput pe
        runtimeTarget.addressMap.candidateInstructionRva
        source.commandInput.candidateDescriptor instructionEntryState =
      StageA.Relational.X87.commandStepInput pe
        runtimeTarget.addressMap.candidateInstructionRva
        source.commandInput.candidateDescriptor source.candidateInput
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
  entryFuel : Nat
  entryFuelPositive : 0 < entryFuel
  instructionFuel : Nat
  instructionFuelPositive : 0 < instructionFuel
  captureFuel : Nat
  captureFuelPositive : 0 < captureFuel
  returnFuel : Nat
  returnFuelPositive : 0 < returnFuel
  callRun :
    runRelatedSteps program.transitionSystem 1
        (.running table.callInstruction.rva 0 caller calls eventIndex events
          world externalFrames) =
      (.running runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  entryRun :
    runRelatedSteps program.transitionSystem entryFuel
        (.running runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running runtimeTarget.target.frameMapping.instructionRva instructionSlot
        instructionEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  instructionRun :
    runRelatedSteps program.transitionSystem instructionFuel
        (.running runtimeTarget.target.frameMapping.instructionRva
          instructionSlot
          instructionEntryState
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running runtimeTarget.target.frameMapping.captureRva captureSlot
        captureEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  captureRun :
    runRelatedSteps program.transitionSystem captureFuel
        (.running runtimeTarget.target.frameMapping.captureRva captureSlot
          captureEntryState
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running runtimeTarget.target.frameMapping.returnRva returnSlot
        returnEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  returnRun :
    runRelatedSteps program.transitionSystem returnFuel
        (.running runtimeTarget.target.frameMapping.returnRva returnSlot
          returnEntryState
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running table.continuationRva 0 returned calls eventIndex events world
        externalFrames, [])
  targetAfter : runtimeTarget.target.descriptor.bridgeCell.Holds pe
    runtimeTarget.target.descriptor.bridge returned
  activeAfter : Memory.read32 returned.memory
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
  outputEncoded : StageA.Relational.Engine.readBytes returned.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
      kernelX87FrameBytes =
    encodeKernelX87Frame candidateResult.state.x87Physical
  faultFree : result.faults = [] ∧ candidateResult.faults = []
  nonX87Output :
    nativeX87ReplayNonX87OutputChecked
      source.toNativeX87ReplayBridgeSourceFrameEvidence returned
      result.state = true
  memoryEffects :
    nativeX87ReplayMemoryEffectsRelated runtimeTarget.addressMap
      result.memoryEffects candidateResult.memoryEffects = true
  physicalState :
    nativeX87ReplayPhysicalStatesRelatedChecked runtimeTarget.addressMap
      result.state.x87Physical candidateResult.state.x87Physical = true

theorem exactNativeX87ReplayFixedTemplateSchedule_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    (nativeX87ReplayFixedTemplateSchedule?
      runtimeTarget.target.frameMapping).isSome = true := by
  have checked := runtimeTarget.layoutChecked
  simp only [nativeX87ReplayBridgeRuntimeChecked, Bool.and_eq_true] at checked
  exact checked.1.2

theorem exactNativeX87ReplayFixedTemplateMixedReplay_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    (nativeX87ReplayFixedTemplateMixedReplay? pe imports
      runtimeTarget.target.frameMapping).isSome = true := by
  have checked := runtimeTarget.layoutChecked
  simp only [nativeX87ReplayBridgeRuntimeChecked, Bool.and_eq_true] at checked
  exact checked.2

theorem exactNativeX87ReplayOriginalSingleton_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    (executeX87Singleton originalPe
      (replayInstructionRecord runtimeTarget.target.descriptor.replay)
      logicalInput).isSome = true := by
  apply executeX87Singleton_isSome_of_decoded originalPe
    (replayInstructionRecord runtimeTarget.target.descriptor.replay)
    logicalInput (by rfl) source.commandInput.originalDescriptor
  exact source.commandInput.originalDecoded

theorem exactNativeX87ReplayCandidateSingleton_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    (executeX87Singleton pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      source.candidateInput).isSome = true := by
  apply executeX87Singleton_isSome_of_decoded pe
    (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
      runtimeTarget.addressMap.candidateInstructionRva)
    source.candidateInput (by rfl) source.commandInput.candidateDescriptor
  exact source.commandInput.candidateDecoded

theorem ExactNativeX87ReplayFixedTemplateStaticExecution.candidateDescriptor_eq
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {originalPe : PE32} {caller logicalInput : MachineState}
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    static.candidateDescriptor =
      source.commandInput.candidateDescriptor := by
  rw [← Option.some.injEq, ← static.candidateDescriptorExact,
    source.commandInput.candidateDecoded]

/-- Exact candidate decoding is static, so singleton existence is available for
every dynamically reconstructed instruction-entry state. -/
theorem ExactNativeX87ReplayFixedTemplateStaticExecution.candidateSingleton_isSome
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (state : MachineState) :
    (executeX87Singleton pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      state).isSome = true := by
  apply executeX87Singleton_isSome_of_decoded pe
    (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
      runtimeTarget.addressMap.candidateInstructionRva)
    state (by rfl) static.candidateDescriptor
  exact static.candidateDescriptorExact

/-- The singleton executor and the mixed native command step share the exact
decoder, command input, qualified parametric semantics, and concrete state
transformer.  A fault-free singleton result therefore determines the native
step endpoint rather than merely predicting a compatible x87 state. -/
theorem executeKernelX87Command?_of_executeX87Singleton
    (pe : PE32) (record : RawInstructionRecord)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (undefinedSlot : Nat) (input : MachineState) (result : StepResult)
    (recordClass : record.decodeClass = some .x87Singleton)
    (decoded :
      StageA.Relational.X87.decodeSingletonCommand pe record.span =
        some descriptor)
    (executed : executeX87Singleton pe record input = some result)
    (faultFree : result.faults = []) :
    executeKernelX87Command? pe record.span.start undefinedSlot input
        descriptor =
      some (.running (record.span.start + descriptor.size)
        (undefinedSlot + 1) result.state) := by
  let witness := executeX87Singleton_witness pe record input result executed
  have descriptorExact : witness.descriptor = descriptor := by
    rw [witness.decoded] at decoded
    exact Option.some.inj decoded
  subst descriptor
  have descriptorSize : witness.descriptor.size = record.span.size := by
    have decodedSize := witness.decoded
    unfold StageA.Relational.X87.decodeSingletonCommand at decodedSize
    rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decodedSize
    obtain ⟨bytes, _bytesExact, decodedSize⟩ := decodedSize
    rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decodedSize
    obtain ⟨decodedDescriptor, _descriptorExact, decodedSize⟩ := decodedSize
    split at decodedSize <;> try contradiction
    rename_i sizeChecked
    simp only [Option.some.injEq] at decodedSize
    subst decodedDescriptor
    exact beq_iff_eq.mp sizeChecked
  have singletonExecuted := witness.executed
  unfold executeKernelX87Command?
  unfold StageA.Relational.X87.executeSingletonCommand at singletonExecuted
  simp [witness.decoded, normalizeCodeTarget, singletonTarget] at singletonExecuted
  cases storeExact :
      (input.x87Semantics.execute witness.descriptor.command
        witness.descriptor.waitMode input.x87Physical
        (StageA.Relational.X87.commandStepInput pe record.span.start
          witness.descriptor input)).store with
  | none =>
      simp [storeExact] at singletonExecuted
      rcases singletonExecuted with
        ⟨inputChecked, waitModeChecked, responseChecked, behaviorExact⟩
      have noFault :
          (input.x87Semantics.execute witness.descriptor.command
            witness.descriptor.waitMode input.x87Physical
            (StageA.Relational.X87.commandStepInput pe record.span.start
              witness.descriptor input)).fault = none := by
        rw [witness.exactFault, ← behaviorExact] at faultFree
        simpa [StageA.Relational.X87.singletonBehavior] using faultFree
      simp [inputChecked, waitModeChecked, responseChecked, noFault, storeExact,
        descriptorSize, Span.stop, witness.resultState, behaviorExact]
      simpa [Span.stop] using
        congrArg (fun behavior : RelationalBehavior =>
          behavior.nextMachineState input) behaviorExact
  | some store =>
      simp only [storeExact] at singletonExecuted
      cases addressExact :
          StageA.Relational.X87.commandDataAddress witness.descriptor input with
      | none => simp [addressExact] at singletonExecuted
      | some address =>
          simp [addressExact] at singletonExecuted
          rcases singletonExecuted with
            ⟨inputChecked, waitModeChecked, responseChecked, behaviorExact⟩
          have noFault :
              (input.x87Semantics.execute witness.descriptor.command
                witness.descriptor.waitMode input.x87Physical
                (StageA.Relational.X87.commandStepInput pe record.span.start
                  witness.descriptor input)).fault = none := by
            rw [witness.exactFault, ← behaviorExact] at faultFree
            simpa [StageA.Relational.X87.singletonBehavior] using faultFree
          simp [inputChecked, waitModeChecked, responseChecked, noFault,
            storeExact, addressExact, descriptorSize, Span.stop,
            witness.resultState, behaviorExact]
          simpa [Span.stop] using
            congrArg (fun behavior : RelationalBehavior =>
              behavior.nextMachineState input) behaviorExact

private theorem decodeSingletonCommand_size
    (pe : PE32) (span : Span)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (decoded :
      StageA.Relational.X87.decodeSingletonCommand pe span =
        some descriptor) :
    descriptor.size = span.size := by
  unfold StageA.Relational.X87.decodeSingletonCommand at decoded
  rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decoded
  obtain ⟨bytes, _bytesExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decoded
  obtain ⟨observed, _descriptorExact, decoded⟩ := decoded
  split at decoded <;> try contradiction
  rename_i sizeChecked
  simp only [Option.some.injEq] at decoded
  subst observed
  exact beq_iff_eq.mp sizeChecked

private theorem nativeX87ReplayFixedTemplateInstructionRegionBound
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    runtimeTarget.target.descriptor.replay.instructionBytes.length <=
      nativeX87ReplayFixedTemplateInstructionRegionSize := by
  have regionSize :
      nativeX87ReplayFixedTemplateInstructionRegionSize = 20 := by decide
  rw [regionSize]
  by_cases bounded :
      runtimeTarget.target.descriptor.replay.instructionBytes.length <=
        20
  · exact bounded
  · have checked := runtimeTarget.target.frameMappingChecked
    simp [NativeX87ReplayBridgeFrameMapping.checked,
      bounded,
      nativeX87ReplayBridgeInstructionOffset,
      nativeX87ReplayBridgeCaptureOffset] at checked
    omega

private theorem nativeX87ReplayFixedTemplateCaptureRva
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    runtimeTarget.target.frameMapping.captureRva =
      runtimeTarget.target.frameMapping.instructionRva +
        nativeX87ReplayFixedTemplateInstructionRegionSize := by
  have regionSize :
      nativeX87ReplayFixedTemplateInstructionRegionSize = 20 := by decide
  rw [regionSize]
  by_cases exact :
      runtimeTarget.target.frameMapping.captureRva =
        runtimeTarget.target.frameMapping.instructionRva +
          20
  · exact exact
  · have checked := runtimeTarget.target.frameMappingChecked
    simp [NativeX87ReplayBridgeFrameMapping.checked,
      exact,
      nativeX87ReplayBridgeInstructionOffset,
      nativeX87ReplayBridgeCaptureOffset] at checked
    omega

private theorem nativeX87ReplayDescriptorSpanSize
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    runtimeTarget.target.descriptor.replay.rvaEnd -
        runtimeTarget.target.descriptor.replay.rvaStart =
      runtimeTarget.target.descriptor.replay.instructionBytes.length := by
  have descriptorChecked :=
    runtimeTarget.target.static.descriptorChecked
      runtimeTarget.target.descriptor runtimeTarget.target.descriptorMember
  have stopExact :
      runtimeTarget.target.descriptor.replay.rvaEnd =
        runtimeTarget.target.descriptor.replay.rvaStart +
          runtimeTarget.target.descriptor.replay.instructionBytes.length := by
    by_cases exact :
        runtimeTarget.target.descriptor.replay.rvaEnd =
          runtimeTarget.target.descriptor.replay.rvaStart +
            runtimeTarget.target.descriptor.replay.instructionBytes.length
    · exact exact
    · simp [NativeX87ReplayBridgeDescriptor.checked, exact] at descriptorChecked
  omega

/-- Execute the variable x87 instruction followed by its checked NOP padding.
The command transition is fixed by the exact candidate decoder, while the x87
response remains parametric in the source state's qualified semantics. -/
private theorem nativeX87ReplayFixedTemplateInstructionRoles_running
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (undefinedSlot : Nat) (input : MachineState)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt
            runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          input =
        some candidateResult)
    (faultFree : candidateResult.faults = []) :
    runNativeX87ReplayTemplateRoles pe imports undefinedSlot input
        (nativeX87ReplayFixedTemplateInstructionRoles
          runtimeTarget.target.frameMapping static.semanticPlan.command) =
      .running runtimeTarget.target.frameMapping.captureRva
        (undefinedSlot +
          (nativeX87ReplayFixedTemplateInstructionRoles
            runtimeTarget.target.frameMapping
            static.semanticPlan.command).length)
        (nativeX87ReplayNopState
          (nativeX87ReplayFixedTemplateInstructionRegionSize -
            static.candidateDescriptor.size)
          candidateResult.state) := by
  have descriptorSize :
      static.candidateDescriptor.size =
        (replayInstructionRecordAt
          runtimeTarget.target.descriptor.replay
          runtimeTarget.addressMap.candidateInstructionRva).span.size :=
    decodeSingletonCommand_size pe _ static.candidateDescriptor
      static.candidateDescriptorExact
  have replaySpanSize :
      (replayInstructionRecordAt
        runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva).span.size =
        runtimeTarget.target.descriptor.replay.instructionBytes.length := by
    simpa [replayInstructionRecordAt, replayInstructionRecord] using
      nativeX87ReplayDescriptorSpanSize runtimeTarget
  have commandExecuted :
      executeKernelX87Command? pe
          runtimeTarget.target.frameMapping.instructionRva undefinedSlot input
          static.candidateDescriptor =
        some (.running
          (runtimeTarget.target.frameMapping.instructionRva +
            static.candidateDescriptor.size)
          (undefinedSlot + 1) candidateResult.state) := by
    apply executeKernelX87Command?_of_executeX87Singleton pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      static.candidateDescriptor undefinedSlot input candidateResult
      (by rfl) static.candidateDescriptorExact candidateExecuted faultFree
  have commandRole :
      (NativeX87ReplayTemplateRole.x87Command
        runtimeTarget.target.frameMapping.instructionRva
        static.semanticPlan.command).semanticStep pe imports undefinedSlot input =
        .running
          (runtimeTarget.target.frameMapping.instructionRva +
            static.candidateDescriptor.size)
          (undefinedSlot + 1) candidateResult.state := by
    simp only [NativeX87ReplayTemplateRole.semanticStep,
      static.semanticCommandExact, commandExecuted]
  let padding :=
    nativeX87ReplayFixedTemplateInstructionRegionSize -
      static.candidateDescriptor.size
  have sizeBound :
      static.candidateDescriptor.size <=
        nativeX87ReplayFixedTemplateInstructionRegionSize := by
    rw [descriptorSize, replaySpanSize]
    exact nativeX87ReplayFixedTemplateInstructionRegionBound runtimeTarget
  have captureRva :=
    nativeX87ReplayFixedTemplateCaptureRva runtimeTarget
  rw [static.semanticCommandExact] at commandRole ⊢
  cases paddingExact : padding with
  | zero =>
      have sizeExact :
          static.candidateDescriptor.size =
            nativeX87ReplayFixedTemplateInstructionRegionSize := by
        dsimp [padding] at paddingExact
        omega
      simp only [nativeX87ReplayFixedTemplateInstructionRoles,
        padding, paddingExact, nativeX87ReplayNopRoles,
        runNativeX87ReplayTemplateRoles, List.length_cons, List.length_nil,
        Nat.add_zero, nativeX87ReplayNopState]
      rw [commandRole, sizeExact, ← captureRva]
  | succ count =>
      have paddingPositive : 0 < padding := by omega
      rw [show nativeX87ReplayFixedTemplateInstructionRoles
          runtimeTarget.target.frameMapping static.candidateDescriptor =
          .x87Command runtimeTarget.target.frameMapping.instructionRva
              static.candidateDescriptor ::
            nativeX87ReplayNopRoles
              (runtimeTarget.target.frameMapping.instructionRva +
                static.candidateDescriptor.size) padding by
        simp [nativeX87ReplayFixedTemplateInstructionRoles, padding]]
      rw [show nativeX87ReplayNopRoles
          (runtimeTarget.target.frameMapping.instructionRva +
            static.candidateDescriptor.size) padding =
          .ordinary
              (runtimeTarget.target.frameMapping.instructionRva +
                static.candidateDescriptor.size) .nop 1 ::
            nativeX87ReplayNopRoles
              (runtimeTarget.target.frameMapping.instructionRva +
                static.candidateDescriptor.size + 1) count by
        simp [nativeX87ReplayNopRoles, paddingExact]]
      rw [runNativeX87ReplayTemplateRoles_cons_running commandRole
        (by simp [NativeX87ReplayTemplateRole.rva])]
      rw [← show nativeX87ReplayNopRoles
          (runtimeTarget.target.frameMapping.instructionRva +
            static.candidateDescriptor.size) padding =
          .ordinary
              (runtimeTarget.target.frameMapping.instructionRva +
                static.candidateDescriptor.size) .nop 1 ::
            nativeX87ReplayNopRoles
              (runtimeTarget.target.frameMapping.instructionRva +
                static.candidateDescriptor.size + 1) count by
        simp [nativeX87ReplayNopRoles, paddingExact]]
      rw [nativeX87ReplayNopRoles_running]
      simp [nativeX87ReplayNopEndpointRva, paddingExact,
        nativeX87ReplayNopRoles, padding, captureRva]
      congr 2 <;> omega

/-! ## Exact capture-state pipeline

The capture trampoline is shared by every replay target.  These definitions
name its three stable state boundaries so the kernel checks each linear
instruction chain once instead of expanding a 36-step term in every theorem. -/

private def nativeX87ReplayFixedTemplateCaptureBeforeSaveState
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (input : MachineState) : MachineState :=
  let flagsSaved := nativeX87ReplayPushFlagsState input
  let eaxSaved := nativeX87ReplayPushRegState .eax flagsSaved
  nativeX87ReplayMovFromOperandState .eax
    (nativeX87ReplayMemory none
      ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) eaxSaved

@[simp] private theorem nativeX87ReplayPushFlagsState_registers
    (input : MachineState) :
    (nativeX87ReplayPushFlagsState input).registers =
      input.registers.set .esp
        (input.registers.esp - BitVec.ofNat 32 4) := by
  simp [nativeX87ReplayPushFlagsState, nativeX87ReplayOrdinaryState,
    nativeX87ReplayPushFlagsBehavior, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, SymbolicBehavior.write32,
    Registers.set, Registers.get, Expr.offset, Expr.addNormalized,
    StageA.Formal.Expr.eval]

@[simp] private theorem nativeX87ReplayPushFlagsState_memory
    (input : MachineState) :
    (nativeX87ReplayPushFlagsState input).memory =
      input.memory.write32
        (input.registers.esp - BitVec.ofNat 32 4)
        ((Expr.bitAnd initialSymbolic.eflagsExpression
          (.constant 0xfffcffff)).eval input) := by
  simp [nativeX87ReplayPushFlagsState, nativeX87ReplayOrdinaryState,
    nativeX87ReplayPushFlagsBehavior, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, SymbolicBehavior.write32,
    Registers.set, Registers.get, Expr.offset, Expr.addNormalized,
    StageA.Formal.Expr.eval, StageA.Formal.applyWrites]

private def nativeX87ReplayFixedTemplateCaptureSavedState
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (frameAddress : Word) (input : MachineState) : MachineState :=
  nativeX87ReplayFnSaveState
    (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input)

private theorem nativeX87ReplayFixedTemplateCaptureSavedState_memoryFrame
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (frameAddress : Word) (input : MachineState) :
    MemoryAgreesOutside
      (nativeX87ReplayByteRange
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
        kernelX87FrameBytes)
      (nativeX87ReplayFixedTemplateCaptureSavedState table pe frameAddress
        input).memory
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input).memory := by
  unfold nativeX87ReplayFixedTemplateCaptureSavedState
  rw [nativeX87ReplayFnSaveState_memory]
  simpa [encodeKernelX87Frame_length] using
    MemoryAgreesOutside.writeX87ByteRange
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input).memory
      (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
      (encodeKernelX87Frame
        (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
          input).x87Physical)

private theorem nativeX87ReplayFixedTemplateCaptureSavedState_registers
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (frameAddress : Word) (input : MachineState) :
    (nativeX87ReplayFixedTemplateCaptureSavedState table pe frameAddress
      input).registers =
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
        input).registers := by
  exact nativeX87ReplayFnSaveState_registers _ _

private def nativeX87ReplayFixedTemplateCaptureOutputLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .edx
    (nativeX87ReplayMemory (some .eax) nativeX87FrameOutputOffset) input

private theorem nativeX87ReplayFixedTemplateCaptureOutputLoadedState_edx
    (input : MachineState) (frameAddress outputAddress : Word)
    (frameExact : input.registers.eax = frameAddress)
    (outputPointer :
      Memory.read32 input.memory
          (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputOffset) =
        outputAddress) :
    (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
      input).registers.edx = outputAddress := by
  unfold nativeX87ReplayFixedTemplateCaptureOutputLoadedState
  change
    (nativeX87ReplayMovFromOperandState .edx
      (nativeX87ReplayMemory (some .eax) nativeX87FrameOutputOffset)
      input).registers.get .edx = outputAddress
  rw [nativeX87ReplayMovFromOperandState_register,
    readNativeX87ReplayMemorySome]
  change Memory.read32 input.memory
    (input.registers.eax + BitVec.ofNat 32 nativeX87FrameOutputOffset) =
      outputAddress
  rw [frameExact]
  exact outputPointer

private def nativeX87ReplayOutputWriteOffsets : List Nat :=
  [0, 32, 48, 36, 40, 44, 240]

private def nativeX87ReplayFlagWriteOffsets : List Nat :=
  [0, 32, 48, 36, 40, 44]

private def nativeX87ReplayOutputWriteFootprint
    (outputAddress : Word) : CandidateFootprint :=
  fun address =>
    ∃ offset ∈ nativeX87ReplayOutputWriteOffsets,
      nativeX87ReplayByteRange
        (outputAddress + BitVec.ofNat 32 offset) 4 address

private def nativeX87ReplayFlagWriteFootprint
    (outputAddress : Word) : CandidateFootprint :=
  fun address =>
    ∃ offset ∈ nativeX87ReplayFlagWriteOffsets,
      nativeX87ReplayByteRange
        (outputAddress + BitVec.ofNat 32 offset) 4 address

private theorem nativeX87ReplayOutputWriteFootprint_observed
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (address : Word)
    (member :
      nativeX87ReplayOutputWriteFootprint source.outputAddress address) :
    Engine.CandidateAddressObserved source.rep address := by
  rcases member with ⟨offset, included, byteMember⟩
  have observedOfEntry :
      ∀ (entry : Engine.EngineFieldLayout),
        entry ∈ source.rep.layout.fields ->
        nativeX87ReplayEngineFieldOffset? entry.field = some offset ->
        entry.field.byteWidth = 4 ->
        Engine.CandidateAddressObserved source.rep address := by
    intro entry entryMember canonical width
    have layout := source.layoutCompatible
    unfold nativeX87ReplayEngineLayoutCompatible at layout
    simp only [Bool.and_eq_true] at layout
    have entryOffset := List.all_eq_true.mp layout.1.2 entry entryMember
    have offsetExact : offset = entry.offset := by
      rw [canonical] at entryOffset
      exact Option.some.inj (beq_iff_eq.mp entryOffset)
    apply Or.inl
    rcases byteMember with ⟨byte, byteBefore, rfl⟩
    refine ⟨entry, entryMember, byte, by simpa [width] using byteBefore, ?_⟩
    simp [Engine.EngineFieldLayout.address, offsetExact, source.engineBase,
      BitVec.add_assoc]
  have requiredEntry :
      ∀ (field : Engine.EngineField),
        field ∈ source.rep.layout.requiredFields ->
        ∃ entry ∈ source.rep.layout.fields, entry.field = field := by
    intro field required
    rcases source.engineRelated.repValid.1 with
      ⟨_stateSizePositive, _stateSizeBound, _fieldsNodup, _fieldsValid,
        _fieldsDisjoint, fieldsComplete⟩
    rcases List.mem_map.mp (fieldsComplete field required) with
      ⟨entry, entryMember, entryField⟩
    exact ⟨entry, entryMember, entryField⟩
  simp only [nativeX87ReplayOutputWriteOffsets, List.mem_cons,
    List.mem_singleton, List.not_mem_nil, or_false] at included
  rcases included with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · rcases requiredEntry (.register .eax) (by
        simp [Engine.EngineLayout.requiredFields, Engine.allRegisters]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)
  · rcases source.flagFieldPresent 0 (by
        simp [nativeX87ReplayRequiredFlagFields]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)
  · rcases source.flagFieldPresent 2 (by
        simp [nativeX87ReplayRequiredFlagFields]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)
  · rcases source.flagFieldPresent 6 (by
        simp [nativeX87ReplayRequiredFlagFields]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)
  · rcases source.flagFieldPresent 7 (by
        simp [nativeX87ReplayRequiredFlagFields]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)
  · rcases source.flagFieldPresent 11 (by
        simp [nativeX87ReplayRequiredFlagFields]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)
  · rcases requiredEntry .eflags (by
        simp [Engine.EngineLayout.requiredFields]) with
      ⟨entry, entryMember, entryField⟩
    exact observedOfEntry entry entryMember
      (by rw [entryField]; rfl) (by rw [entryField]; rfl)

private theorem nativeX87ReplayFlagWriteFootprint_observed
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (address : Word)
    (member :
      nativeX87ReplayFlagWriteFootprint source.outputAddress address) :
    Engine.CandidateAddressObserved source.rep address := by
  apply nativeX87ReplayOutputWriteFootprint_observed source address
  rcases member with ⟨offset, included, byteMember⟩
  refine ⟨offset, ?_, byteMember⟩
  simp only [nativeX87ReplayFlagWriteOffsets, nativeX87ReplayOutputWriteOffsets,
    List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at included ⊢
  rcases included with rfl | rfl | rfl | rfl | rfl | rfl
  all_goals simp

private theorem nativeX87ReplayFlagWriteFootprint_disjointEflags
    (outputAddress : Word) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFlagWriteFootprint outputAddress)
      (nativeX87ReplayByteRange
        (outputAddress + BitVec.ofNat 32 240) 4) := by
  intro address writeMember eflagsMember
  rcases writeMember with ⟨offset, included, byteMember⟩
  simp only [nativeX87ReplayFlagWriteOffsets, List.mem_cons,
    List.mem_singleton, List.not_mem_nil, or_false] at included
  rcases included with rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    exact
      (translatedByteRangesDisjoint outputAddress _ 4 240 4
        (by decide) (by decide) (Or.inl (by decide)))
        address byteMember eflagsMember

private theorem nativeX87ReplayOutputWriteAgreesOutside
    (before : Memory) (outputAddress : Word) (offset : Nat) (value : Word)
    (included : offset ∈ nativeX87ReplayOutputWriteOffsets) :
    MemoryAgreesOutside
      (nativeX87ReplayOutputWriteFootprint outputAddress)
      (before.write32 (outputAddress + BitVec.ofNat 32 offset) value)
      before := by
  apply MemoryAgreesOutside.write32Inside
  intro byte byteBefore
  exact ⟨offset, included, ⟨byte, byteBefore, rfl⟩⟩

private def nativeX87ReplayFixedTemplateCaptureEaxRecoveredState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ecx
    (nativeX87ReplayMemory (some .esp) 0)
    (nativeX87ReplayFixedTemplateCaptureOutputLoadedState input)

private def nativeX87ReplayFixedTemplateCaptureEaxWrittenState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovToMemoryState
    (nativeX87ReplayAddressing (some .edx) 0) .ecx
    (nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input)

private def nativeX87ReplayFixedTemplateCaptureCfWrittenState
    (input : MachineState) : MachineState :=
  nativeX87ReplaySetConditionMemoryState .below
    (nativeX87ReplayAddressing (some .edx) 32)
    (nativeX87ReplayFixedTemplateCaptureEaxWrittenState input)

private def nativeX87ReplayFixedTemplateCapturePfWrittenState
    (input : MachineState) : MachineState :=
  nativeX87ReplaySetConditionMemoryState .parity
    (nativeX87ReplayAddressing (some .edx) 48)
    (nativeX87ReplayFixedTemplateCaptureCfWrittenState input)

private def nativeX87ReplayFixedTemplateCaptureZfWrittenState
    (input : MachineState) : MachineState :=
  nativeX87ReplaySetConditionMemoryState .equal
    (nativeX87ReplayAddressing (some .edx) 36)
    (nativeX87ReplayFixedTemplateCapturePfWrittenState input)

private def nativeX87ReplayFixedTemplateCaptureSfWrittenState
    (input : MachineState) : MachineState :=
  nativeX87ReplaySetConditionMemoryState .sign
    (nativeX87ReplayAddressing (some .edx) 40)
    (nativeX87ReplayFixedTemplateCaptureZfWrittenState input)

private def nativeX87ReplayFixedTemplateCaptureOfWrittenState
    (input : MachineState) : MachineState :=
  nativeX87ReplaySetConditionMemoryState .overflow
    (nativeX87ReplayAddressing (some .edx) 44)
    (nativeX87ReplayFixedTemplateCaptureSfWrittenState input)

private def nativeX87ReplayFixedTemplateCaptureSavedFlagsState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ebx
    (nativeX87ReplayMemory (some .esp) 4)
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState input)

private def nativeX87ReplayFixedTemplateCaptureInputLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ecx
    (nativeX87ReplayMemory (some .eax) nativeX87FrameInputOffset)
    (nativeX87ReplayFixedTemplateCaptureSavedFlagsState input)

private def nativeX87ReplayFixedTemplateCaptureInputFlagsState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ecx
    (nativeX87ReplayMemory (some .ecx) 240)
    (nativeX87ReplayFixedTemplateCaptureInputLoadedState input)

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedFlagsState_ebx
    (input : MachineState) (value : Word)
    (saved :
      Memory.read32
          (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
          ((nativeX87ReplayFixedTemplateCaptureOfWrittenState
              input).registers.get .esp + BitVec.ofNat 32 4) = value) :
    (nativeX87ReplayFixedTemplateCaptureSavedFlagsState
      input).registers.get .ebx = value := by
  unfold nativeX87ReplayFixedTemplateCaptureSavedFlagsState
  rw [nativeX87ReplayMovFromOperandState_register,
    readNativeX87ReplayMemorySome, saved]

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedFlagsState_register_other
    (input : MachineState) (register : Reg) (value : Word)
    (different : register ≠ .ebx)
    (before :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get register = value) :
    (nativeX87ReplayFixedTemplateCaptureSavedFlagsState
      input).registers.get register =
      value :=
  (nativeX87ReplayMovFromOperandState_register_other .ebx register
    (nativeX87ReplayMemory (some .esp) 4)
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState input)
    different).trans before

private theorem
    nativeX87ReplayFixedTemplateCaptureInputLoadedState_ecx
    (input : MachineState) (frameAddress inputAddress : Word)
    (frameExact :
      (nativeX87ReplayFixedTemplateCaptureSavedFlagsState
        input).registers.get .eax = frameAddress)
    (inputPointer :
      Memory.read32
          (nativeX87ReplayFixedTemplateCaptureSavedFlagsState input).memory
          (frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) =
        inputAddress) :
    (nativeX87ReplayFixedTemplateCaptureInputLoadedState
      input).registers.get .ecx = inputAddress := by
  unfold nativeX87ReplayFixedTemplateCaptureInputLoadedState
  rw [nativeX87ReplayMovFromOperandState_register,
    readNativeX87ReplayMemorySome, frameExact, inputPointer]

private theorem
    nativeX87ReplayFixedTemplateCaptureInputFlagsState_ecx
    (input : MachineState) (inputAddress eflags : Word)
    (inputLoaded :
      (nativeX87ReplayFixedTemplateCaptureInputLoadedState
        input).registers.get .ecx = inputAddress)
    (inputEflags :
      Memory.read32
          (nativeX87ReplayFixedTemplateCaptureInputLoadedState input).memory
          (inputAddress + BitVec.ofNat 32 240) = eflags) :
    (nativeX87ReplayFixedTemplateCaptureInputFlagsState
      input).registers.get .ecx = eflags := by
  unfold nativeX87ReplayFixedTemplateCaptureInputFlagsState
  rw [nativeX87ReplayMovFromOperandState_register,
    readNativeX87ReplayMemorySome, inputLoaded, inputEflags]

private theorem
    nativeX87ReplayFixedTemplateCaptureInputFlagsState_ebx
    (input : MachineState) (value : Word)
    (saved :
      (nativeX87ReplayFixedTemplateCaptureSavedFlagsState
        input).registers.get .ebx = value) :
    (nativeX87ReplayFixedTemplateCaptureInputFlagsState
      input).registers.get .ebx = value := by
  calc
    _ = (nativeX87ReplayFixedTemplateCaptureInputLoadedState
          input).registers.get .ebx :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .ebx
        (nativeX87ReplayMemory (some .ecx) 240)
        (nativeX87ReplayFixedTemplateCaptureInputLoadedState input) (by decide)
    _ = (nativeX87ReplayFixedTemplateCaptureSavedFlagsState
          input).registers.get .ebx :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .ebx
        (nativeX87ReplayMemory (some .eax) nativeX87FrameInputOffset)
        (nativeX87ReplayFixedTemplateCaptureSavedFlagsState input) (by decide)
    _ = value := saved

private def nativeX87ReplayFixedTemplateCapturePreservedFlagsState
    (undefinedSlot : Nat) (input : MachineState) : MachineState :=
  nativeX87ReplayAndRegisterState (undefinedSlot + 15) .ecx
    (.immediate 0xfffff32a)
    (nativeX87ReplayFixedTemplateCaptureInputFlagsState input)

private def nativeX87ReplayFixedTemplateCaptureResultFlagsState
    (undefinedSlot : Nat) (input : MachineState) : MachineState :=
  nativeX87ReplayAndRegisterState (undefinedSlot + 16) .ebx
    (.immediate 0x0cd5)
    (nativeX87ReplayFixedTemplateCapturePreservedFlagsState
      undefinedSlot input)

private def nativeX87ReplayFixedTemplateCaptureMergedFlagsState
    (undefinedSlot : Nat) (input : MachineState) : MachineState :=
  nativeX87ReplayOrRegisterState (undefinedSlot + 17) .ecx
    (.register .ebx)
    (nativeX87ReplayFixedTemplateCaptureResultFlagsState undefinedSlot input)

private def nativeX87ReplayFixedTemplateOutputWrittenState
    (undefinedSlot : Nat) (frameAddress : Word)
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovToMemoryState
    (nativeX87ReplayAddressing (some .edx) 240) .ecx
    (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot input)

private theorem nativeX87ReplayMergedFlagsState_ecx
    (undefinedSlot : Nat) (input : MachineState)
    (inputEflags resultEflags : Word)
    (inputExact : input.registers.get .ecx = inputEflags)
    (resultExact : input.registers.get .ebx = resultEflags)
    (mergedExact :
      (inputEflags &&& BitVec.ofNat 32 0xfffff32a) |||
          (resultEflags &&& BitVec.ofNat 32 0x0cd5) =
        resultEflags) :
    (nativeX87ReplayOrRegisterState (undefinedSlot + 17) .ecx
      (.register .ebx)
      (nativeX87ReplayAndRegisterState (undefinedSlot + 16) .ebx
        (.immediate 0x0cd5)
        (nativeX87ReplayAndRegisterState (undefinedSlot + 15) .ecx
          (.immediate 0xfffff32a) input))).registers.get .ecx =
      resultEflags := by
  let preserved :=
    nativeX87ReplayAndRegisterState (undefinedSlot + 15) .ecx
      (.immediate 0xfffff32a) input
  let result :=
    nativeX87ReplayAndRegisterState (undefinedSlot + 16) .ebx
      (.immediate 0x0cd5) preserved
  have preservedEcx :
      preserved.registers.get .ecx =
        inputEflags &&& BitVec.ofNat 32 0xfffff32a := by
    calc
      _ = input.registers.get .ecx &&&
          (readOperand32 initialSymbolic
            (.immediate 0xfffff32a)).eval input :=
        nativeX87ReplayAndRegisterState_register
          (undefinedSlot + 15) .ecx (.immediate 0xfffff32a) input
      _ = inputEflags &&& BitVec.ofNat 32 0xfffff32a := by
        simp [inputExact, readOperand32, StageA.Formal.Expr.eval]
  have resultEbx :
      result.registers.get .ebx =
        resultEflags &&& BitVec.ofNat 32 0x0cd5 := by
    have preservedEbx :
        preserved.registers.get .ebx = input.registers.get .ebx := by
      exact nativeX87ReplayAndRegisterState_register_other
        (undefinedSlot + 15) .ecx .ebx (.immediate 0xfffff32a)
        input (by decide)
    calc
      _ = preserved.registers.get .ebx &&&
          (readOperand32 initialSymbolic
            (.immediate 0x0cd5)).eval preserved :=
        nativeX87ReplayAndRegisterState_register
          (undefinedSlot + 16) .ebx (.immediate 0x0cd5) preserved
      _ = input.registers.get .ebx &&&
          BitVec.ofNat 32 0x0cd5 := by
        rw [preservedEbx]
        simp [readOperand32, StageA.Formal.Expr.eval]
      _ = resultEflags &&& BitVec.ofNat 32 0x0cd5 := by rw [resultExact]
  have resultEcx :
      result.registers.get .ecx = preserved.registers.get .ecx := by
    change
      (nativeX87ReplayAndRegisterState (undefinedSlot + 16) .ebx
        (.immediate 0x0cd5) preserved).registers.get .ecx =
          preserved.registers.get .ecx
    exact nativeX87ReplayAndRegisterState_register_other
      (undefinedSlot + 16) .ebx .ecx (.immediate 0x0cd5)
      preserved (by decide)
  calc
    _ = result.registers.get .ecx |||
        (readOperand32 initialSymbolic (.register .ebx)).eval result :=
      nativeX87ReplayOrRegisterState_register
        (undefinedSlot + 17) .ecx (.register .ebx) result
    _ = preserved.registers.get .ecx ||| result.registers.get .ebx := by
      rw [resultEcx]
      rw [readOperand32_initialSymbolic_eval]
      rfl
    _ = resultEflags := by rw [preservedEcx, resultEbx, mergedExact]

private theorem nativeX87ReplayMovToOutputState_memoryFrame
    (source : Reg) (offset : Nat) (input : MachineState)
    (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress)
    (included : offset ∈ nativeX87ReplayOutputWriteOffsets) :
    MemoryAgreesOutside
      (nativeX87ReplayOutputWriteFootprint outputAddress)
      (nativeX87ReplayMovToMemoryState
        (nativeX87ReplayAddressing (some .edx) offset) source input).memory
      input.memory := by
  rw [nativeX87ReplayMovToMemoryState_memory,
    nativeX87ReplayAddressing_some_eval, edxExact]
  exact nativeX87ReplayOutputWriteAgreesOutside input.memory outputAddress
    offset (input.registers.get source) included

private theorem nativeX87ReplayMovToFlagWriteState_memoryFrame
    (source : Reg) (offset : Nat) (input : MachineState)
    (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress)
    (included : offset ∈ nativeX87ReplayFlagWriteOffsets) :
    MemoryAgreesOutside
      (nativeX87ReplayFlagWriteFootprint outputAddress)
      (nativeX87ReplayMovToMemoryState
        (nativeX87ReplayAddressing (some .edx) offset) source input).memory
      input.memory := by
  rw [nativeX87ReplayMovToMemoryState_memory,
    nativeX87ReplayAddressing_some_eval, edxExact]
  apply MemoryAgreesOutside.write32Inside
  intro byte byteBefore
  exact ⟨offset, included, ⟨byte, byteBefore, rfl⟩⟩

private theorem nativeX87ReplaySetConditionOutputState_memoryFrame
    (condition : Condition) (offset : Nat) (input : MachineState)
    (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress)
    (included : offset ∈ nativeX87ReplayOutputWriteOffsets) :
    MemoryAgreesOutside
      (nativeX87ReplayOutputWriteFootprint outputAddress)
      (nativeX87ReplaySetConditionMemoryState condition
        (nativeX87ReplayAddressing (some .edx) offset) input).memory
      input.memory := by
  have framed :=
    nativeX87ReplaySetConditionMemoryState_memoryFrame condition
      (nativeX87ReplayAddressing (some .edx) offset) input
  rw [nativeX87ReplayAddressing_some_eval, edxExact] at framed
  exact MemoryAgreesOutside.widen framed (by
      intro address member
      exact ⟨offset, included, member⟩)

private theorem nativeX87ReplaySetConditionFlagWriteState_memoryFrame
    (condition : Condition) (offset : Nat) (input : MachineState)
    (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress)
    (included : offset ∈ nativeX87ReplayFlagWriteOffsets) :
    MemoryAgreesOutside
      (nativeX87ReplayFlagWriteFootprint outputAddress)
      (nativeX87ReplaySetConditionMemoryState condition
        (nativeX87ReplayAddressing (some .edx) offset) input).memory
      input.memory := by
  have framed :=
    nativeX87ReplaySetConditionMemoryState_memoryFrame condition
      (nativeX87ReplayAddressing (some .edx) offset) input
  rw [nativeX87ReplayAddressing_some_eval, edxExact] at framed
  exact MemoryAgreesOutside.widen framed (by
      intro address member
      exact ⟨offset, included, member⟩)

private theorem nativeX87ReplayMovToOutputState_read32_same
    (source : Reg) (offset : Nat) (input : MachineState)
    (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress) :
    Memory.read32
        (nativeX87ReplayMovToMemoryState
          (nativeX87ReplayAddressing (some .edx) offset) source input).memory
        (outputAddress + BitVec.ofNat 32 offset) =
      input.registers.get source := by
  rw [nativeX87ReplayMovToMemoryState_memory,
    nativeX87ReplayAddressing_some_eval, edxExact]
  exact Memory.read32_write32_same _ _ _

private theorem nativeX87ReplayMovToOutputState_read32_other
    (source : Reg) (writeOffset readOffset : Nat) (input : MachineState)
    (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress)
    (writeBounded : writeOffset + 4 <= 2 ^ 32)
    (readBounded : readOffset + 4 <= 2 ^ 32)
    (separated :
      writeOffset + 4 <= readOffset ∨ readOffset + 4 <= writeOffset) :
    Memory.read32
        (nativeX87ReplayMovToMemoryState
          (nativeX87ReplayAddressing (some .edx) writeOffset) source
          input).memory
        (outputAddress + BitVec.ofNat 32 readOffset) =
      Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 readOffset) := by
  rw [nativeX87ReplayMovToMemoryState_memory,
    nativeX87ReplayAddressing_some_eval, edxExact]
  exact Memory.read32_write32_translated_of_disjoint input.memory outputAddress
    writeOffset readOffset (input.registers.get source)
    writeBounded readBounded separated

private theorem nativeX87ReplaySetConditionOutputState_read32_other
    (condition : Condition) (writeOffset readOffset : Nat)
    (input : MachineState) (outputAddress : Word)
    (edxExact : input.registers.get .edx = outputAddress)
    (writeBounded : writeOffset + 4 <= 2 ^ 32)
    (readBounded : readOffset + 4 <= 2 ^ 32)
    (separated :
      writeOffset + 4 <= readOffset ∨ readOffset + 4 <= writeOffset) :
    Memory.read32
        (nativeX87ReplaySetConditionMemoryState condition
          (nativeX87ReplayAddressing (some .edx) writeOffset) input).memory
        (outputAddress + BitVec.ofNat 32 readOffset) =
      Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 readOffset) := by
  have frame :=
    nativeX87ReplaySetConditionMemoryState_memoryFrame condition
      (nativeX87ReplayAddressing (some .edx) writeOffset) input
  rw [nativeX87ReplayAddressing_some_eval, edxExact] at frame
  exact MemoryAgreesOutside.read32_of_disjoint frame
    (translatedByteRangesDisjoint outputAddress writeOffset 4 readOffset 4
      writeBounded readBounded separated)

private theorem
    nativeX87ReplayFixedTemplateCaptureOfWrittenState_memoryFrame
    (input : MachineState) (outputAddress : Word)
    (outputLoaded :
      (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
        input).registers.get .edx = outputAddress) :
    MemoryAgreesOutside
      (nativeX87ReplayFlagWriteFootprint outputAddress)
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
      input.memory := by
  let loaded := nativeX87ReplayFixedTemplateCaptureOutputLoadedState input
  let recovered := nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input
  let eaxWritten := nativeX87ReplayFixedTemplateCaptureEaxWrittenState input
  let cfWritten := nativeX87ReplayFixedTemplateCaptureCfWrittenState input
  let pfWritten := nativeX87ReplayFixedTemplateCapturePfWrittenState input
  let zfWritten := nativeX87ReplayFixedTemplateCaptureZfWrittenState input
  let sfWritten := nativeX87ReplayFixedTemplateCaptureSfWrittenState input
  let ofWritten := nativeX87ReplayFixedTemplateCaptureOfWrittenState input
  have loadedMemory : loaded.memory = input.memory := by
    dsimp [loaded, nativeX87ReplayFixedTemplateCaptureOutputLoadedState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have recoveredMemory : recovered.memory = loaded.memory := by
    dsimp [recovered, nativeX87ReplayFixedTemplateCaptureEaxRecoveredState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have recoveredEdx : recovered.registers.get .edx = outputAddress := by
    refine (nativeX87ReplayMovFromOperandState_register_other .ecx .edx
      (nativeX87ReplayMemory (some .esp) 0) loaded (by decide)).trans ?_
    simpa [loaded] using outputLoaded
  have eaxFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint outputAddress)
        eaxWritten.memory recovered.memory := by
    simpa only [eaxWritten,
      nativeX87ReplayFixedTemplateCaptureEaxWrittenState] using
      nativeX87ReplayMovToFlagWriteState_memoryFrame .ecx 0 recovered
        outputAddress recoveredEdx (by decide)
  have eaxEdx : eaxWritten.registers.get .edx = outputAddress := by
    dsimp [eaxWritten, nativeX87ReplayFixedTemplateCaptureEaxWrittenState]
    rw [nativeX87ReplayMovToMemoryState_registers]
    exact recoveredEdx
  have cfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint outputAddress)
        cfWritten.memory eaxWritten.memory := by
    simpa only [cfWritten,
      nativeX87ReplayFixedTemplateCaptureCfWrittenState] using
      nativeX87ReplaySetConditionFlagWriteState_memoryFrame .below 32 eaxWritten
        outputAddress eaxEdx (by decide)
  have cfEdx : cfWritten.registers.get .edx = outputAddress := by
    dsimp [cfWritten, nativeX87ReplayFixedTemplateCaptureCfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact eaxEdx
  have pfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint outputAddress)
        pfWritten.memory cfWritten.memory := by
    simpa only [pfWritten,
      nativeX87ReplayFixedTemplateCapturePfWrittenState] using
      nativeX87ReplaySetConditionFlagWriteState_memoryFrame .parity 48 cfWritten
        outputAddress cfEdx (by decide)
  have pfEdx : pfWritten.registers.get .edx = outputAddress := by
    dsimp [pfWritten, nativeX87ReplayFixedTemplateCapturePfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact cfEdx
  have zfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint outputAddress)
        zfWritten.memory pfWritten.memory := by
    simpa only [zfWritten,
      nativeX87ReplayFixedTemplateCaptureZfWrittenState] using
      nativeX87ReplaySetConditionFlagWriteState_memoryFrame .equal 36 pfWritten
        outputAddress pfEdx (by decide)
  have zfEdx : zfWritten.registers.get .edx = outputAddress := by
    dsimp [zfWritten, nativeX87ReplayFixedTemplateCaptureZfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact pfEdx
  have sfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint outputAddress)
        sfWritten.memory zfWritten.memory := by
    simpa only [sfWritten,
      nativeX87ReplayFixedTemplateCaptureSfWrittenState] using
      nativeX87ReplaySetConditionFlagWriteState_memoryFrame .sign 40 zfWritten
        outputAddress zfEdx (by decide)
  have sfEdx : sfWritten.registers.get .edx = outputAddress := by
    dsimp [sfWritten, nativeX87ReplayFixedTemplateCaptureSfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact zfEdx
  have ofFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint outputAddress)
        ofWritten.memory sfWritten.memory := by
    simpa only [ofWritten,
      nativeX87ReplayFixedTemplateCaptureOfWrittenState] using
      nativeX87ReplaySetConditionFlagWriteState_memoryFrame .overflow 44 sfWritten
        outputAddress sfEdx (by decide)
  rw [recoveredMemory, loadedMemory] at eaxFrame
  exact (((((eaxFrame.trans cfFrame).trans pfFrame).trans zfFrame).trans
    sfFrame).trans ofFrame)

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_memoryFrame
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState)
    (outputLoaded :
      (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
        input).registers.get .edx = outputAddress) :
    MemoryAgreesOutside
      (nativeX87ReplayOutputWriteFootprint outputAddress)
      (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot frameAddress
        input).memory
      input.memory := by
  let loaded := nativeX87ReplayFixedTemplateCaptureOutputLoadedState input
  let recovered := nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input
  let eaxWritten := nativeX87ReplayFixedTemplateCaptureEaxWrittenState input
  let cfWritten := nativeX87ReplayFixedTemplateCaptureCfWrittenState input
  let pfWritten := nativeX87ReplayFixedTemplateCapturePfWrittenState input
  let zfWritten := nativeX87ReplayFixedTemplateCaptureZfWrittenState input
  let sfWritten := nativeX87ReplayFixedTemplateCaptureSfWrittenState input
  let ofWritten := nativeX87ReplayFixedTemplateCaptureOfWrittenState input
  let savedFlags := nativeX87ReplayFixedTemplateCaptureSavedFlagsState input
  let inputLoaded := nativeX87ReplayFixedTemplateCaptureInputLoadedState input
  let inputFlags := nativeX87ReplayFixedTemplateCaptureInputFlagsState input
  let preserved :=
    nativeX87ReplayFixedTemplateCapturePreservedFlagsState undefinedSlot input
  let result :=
    nativeX87ReplayFixedTemplateCaptureResultFlagsState undefinedSlot input
  let merged :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot input
  have loadedMemory : loaded.memory = input.memory := by
    dsimp [loaded, nativeX87ReplayFixedTemplateCaptureOutputLoadedState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have recoveredMemory : recovered.memory = loaded.memory := by
    dsimp [recovered, nativeX87ReplayFixedTemplateCaptureEaxRecoveredState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have recoveredEdx : recovered.registers.get .edx = outputAddress := by
    refine (nativeX87ReplayMovFromOperandState_register_other .ecx .edx
      (nativeX87ReplayMemory (some .esp) 0) loaded (by decide)).trans
        ?_
    simpa [loaded] using outputLoaded
  have eaxFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        eaxWritten.memory recovered.memory := by
    simpa only [eaxWritten,
      nativeX87ReplayFixedTemplateCaptureEaxWrittenState] using
      nativeX87ReplayMovToOutputState_memoryFrame .ecx 0 recovered
        outputAddress recoveredEdx (by decide)
  have eaxEdx : eaxWritten.registers.get .edx = outputAddress := by
    dsimp [eaxWritten,
      nativeX87ReplayFixedTemplateCaptureEaxWrittenState]
    rw [nativeX87ReplayMovToMemoryState_registers]
    exact recoveredEdx
  have cfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        cfWritten.memory eaxWritten.memory := by
    simpa only [cfWritten,
      nativeX87ReplayFixedTemplateCaptureCfWrittenState] using
      nativeX87ReplaySetConditionOutputState_memoryFrame .below 32 eaxWritten
        outputAddress eaxEdx (by decide)
  have cfEdx : cfWritten.registers.get .edx = outputAddress := by
    dsimp [cfWritten, nativeX87ReplayFixedTemplateCaptureCfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact eaxEdx
  have pfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        pfWritten.memory cfWritten.memory := by
    simpa only [pfWritten,
      nativeX87ReplayFixedTemplateCapturePfWrittenState] using
      nativeX87ReplaySetConditionOutputState_memoryFrame .parity 48 cfWritten
        outputAddress cfEdx (by decide)
  have pfEdx : pfWritten.registers.get .edx = outputAddress := by
    dsimp [pfWritten, nativeX87ReplayFixedTemplateCapturePfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact cfEdx
  have zfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        zfWritten.memory pfWritten.memory := by
    simpa only [zfWritten,
      nativeX87ReplayFixedTemplateCaptureZfWrittenState] using
      nativeX87ReplaySetConditionOutputState_memoryFrame .equal 36 pfWritten
        outputAddress pfEdx (by decide)
  have zfEdx : zfWritten.registers.get .edx = outputAddress := by
    dsimp [zfWritten, nativeX87ReplayFixedTemplateCaptureZfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact pfEdx
  have sfFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        sfWritten.memory zfWritten.memory := by
    simpa only [sfWritten,
      nativeX87ReplayFixedTemplateCaptureSfWrittenState] using
      nativeX87ReplaySetConditionOutputState_memoryFrame .sign 40 zfWritten
        outputAddress zfEdx (by decide)
  have sfEdx : sfWritten.registers.get .edx = outputAddress := by
    dsimp [sfWritten, nativeX87ReplayFixedTemplateCaptureSfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact zfEdx
  have ofFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        ofWritten.memory sfWritten.memory := by
    simpa only [ofWritten,
      nativeX87ReplayFixedTemplateCaptureOfWrittenState] using
      nativeX87ReplaySetConditionOutputState_memoryFrame .overflow 44 sfWritten
        outputAddress sfEdx (by decide)
  have ofEdx : ofWritten.registers.get .edx = outputAddress := by
    dsimp [ofWritten, nativeX87ReplayFixedTemplateCaptureOfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_registers]
    exact sfEdx
  have savedMemory : savedFlags.memory = ofWritten.memory := by
    dsimp [savedFlags,
      nativeX87ReplayFixedTemplateCaptureSavedFlagsState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have savedEdx : savedFlags.registers.get .edx = outputAddress := by
    exact (nativeX87ReplayMovFromOperandState_register_other .ebx .edx
      (nativeX87ReplayMemory (some .esp) 4) ofWritten
      (by decide)).trans ofEdx
  have inputLoadedMemory : inputLoaded.memory = savedFlags.memory := by
    dsimp [inputLoaded,
      nativeX87ReplayFixedTemplateCaptureInputLoadedState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have inputLoadedEdx : inputLoaded.registers.get .edx = outputAddress := by
    exact (nativeX87ReplayMovFromOperandState_register_other .ecx .edx
      (nativeX87ReplayMemory (some .eax) nativeX87FrameInputOffset)
      savedFlags (by decide)).trans savedEdx
  have inputFlagsMemory : inputFlags.memory = inputLoaded.memory := by
    dsimp [inputFlags,
      nativeX87ReplayFixedTemplateCaptureInputFlagsState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have inputFlagsEdx : inputFlags.registers.get .edx = outputAddress := by
    exact (nativeX87ReplayMovFromOperandState_register_other .ecx .edx
      (nativeX87ReplayMemory (some .ecx) 240) inputLoaded
      (by decide)).trans inputLoadedEdx
  have preservedMemory : preserved.memory = inputFlags.memory := by
    dsimp [preserved,
      nativeX87ReplayFixedTemplateCapturePreservedFlagsState]
    exact nativeX87ReplayAndRegisterState_memory _ _ _ _
  have preservedEdx : preserved.registers.get .edx = outputAddress := by
    exact (nativeX87ReplayAndRegisterState_register_other
      (undefinedSlot + 15) .ecx .edx (.immediate 0xfffff32a) inputFlags
      (by decide)).trans inputFlagsEdx
  have resultMemory : result.memory = preserved.memory := by
    dsimp [result,
      nativeX87ReplayFixedTemplateCaptureResultFlagsState]
    exact nativeX87ReplayAndRegisterState_memory _ _ _ _
  have resultEdx : result.registers.get .edx = outputAddress := by
    exact (nativeX87ReplayAndRegisterState_register_other
      (undefinedSlot + 16) .ebx .edx (.immediate 0x0cd5) preserved
      (by decide)).trans preservedEdx
  have mergedMemory : merged.memory = result.memory := by
    dsimp [merged,
      nativeX87ReplayFixedTemplateCaptureMergedFlagsState]
    exact nativeX87ReplayOrRegisterState_memory _ _ _ _
  have mergedEdx : merged.registers.get .edx = outputAddress := by
    exact (nativeX87ReplayOrRegisterState_register_other
      (undefinedSlot + 17) .ecx .edx (.register .ebx) result
      (by decide)).trans resultEdx
  have finalFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory merged.memory := by
    simpa only [nativeX87ReplayFixedTemplateOutputWrittenState, merged] using
      nativeX87ReplayMovToOutputState_memoryFrame .ecx 240 merged
        outputAddress mergedEdx (by decide)
  rw [recoveredMemory, loadedMemory] at eaxFrame
  rw [savedMemory] at inputLoadedMemory
  rw [inputLoadedMemory] at inputFlagsMemory
  rw [inputFlagsMemory] at preservedMemory
  rw [preservedMemory] at resultMemory
  rw [resultMemory] at mergedMemory
  rw [mergedMemory] at finalFrame
  exact (((((eaxFrame.trans cfFrame).trans pfFrame).trans zfFrame).trans
    sfFrame).trans ofFrame).trans finalFrame

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_eax
    (undefinedSlot : Nat) (frameAddress : Word) (input : MachineState) :
    (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot frameAddress
      input).registers.get .eax =
      input.registers.get .eax := by
  let loaded := nativeX87ReplayFixedTemplateCaptureOutputLoadedState input
  let recovered := nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input
  let eaxWritten := nativeX87ReplayFixedTemplateCaptureEaxWrittenState input
  let cfWritten := nativeX87ReplayFixedTemplateCaptureCfWrittenState input
  let pfWritten := nativeX87ReplayFixedTemplateCapturePfWrittenState input
  let zfWritten := nativeX87ReplayFixedTemplateCaptureZfWrittenState input
  let sfWritten := nativeX87ReplayFixedTemplateCaptureSfWrittenState input
  let ofWritten := nativeX87ReplayFixedTemplateCaptureOfWrittenState input
  let savedFlags := nativeX87ReplayFixedTemplateCaptureSavedFlagsState input
  let inputLoaded := nativeX87ReplayFixedTemplateCaptureInputLoadedState input
  let inputFlags := nativeX87ReplayFixedTemplateCaptureInputFlagsState input
  let preserved :=
    nativeX87ReplayFixedTemplateCapturePreservedFlagsState undefinedSlot input
  let result :=
    nativeX87ReplayFixedTemplateCaptureResultFlagsState undefinedSlot input
  let merged :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot input
  calc
    (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot frameAddress
        input).registers.get .eax =
        merged.registers.get .eax := by
      simpa [nativeX87ReplayFixedTemplateOutputWrittenState, merged] using
        congrArg (fun registers => registers.get .eax)
          (nativeX87ReplayMovToMemoryState_registers
            (nativeX87ReplayAddressing (some .edx) 240) .ecx merged)
    _ = result.registers.get .eax :=
      nativeX87ReplayOrRegisterState_register_other
        (undefinedSlot + 17) .ecx .eax (.register .ebx) result (by decide)
    _ = preserved.registers.get .eax :=
      nativeX87ReplayAndRegisterState_register_other
        (undefinedSlot + 16) .ebx .eax (.immediate 0x0cd5) preserved
        (by decide)
    _ = inputFlags.registers.get .eax :=
      nativeX87ReplayAndRegisterState_register_other
        (undefinedSlot + 15) .ecx .eax (.immediate 0xfffff32a) inputFlags
        (by decide)
    _ = inputLoaded.registers.get .eax :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .eax
        (nativeX87ReplayMemory (some .ecx) 240) inputLoaded (by decide)
    _ = savedFlags.registers.get .eax :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .eax
        (nativeX87ReplayMemory (some .eax) nativeX87FrameInputOffset)
        savedFlags (by decide)
    _ = ofWritten.registers.get .eax :=
      nativeX87ReplayMovFromOperandState_register_other .ebx .eax
        (nativeX87ReplayMemory (some .esp) 4) ofWritten (by decide)
    _ = sfWritten.registers.get .eax := by
      change (nativeX87ReplaySetConditionMemoryState .overflow
        (nativeX87ReplayAddressing (some .edx) 44)
        sfWritten).registers.get .eax = sfWritten.registers.get .eax
      exact congrArg (fun registers => registers.get .eax)
        (nativeX87ReplaySetConditionMemoryState_registers .overflow
          (nativeX87ReplayAddressing (some .edx) 44) sfWritten)
    _ = zfWritten.registers.get .eax := by
      change (nativeX87ReplaySetConditionMemoryState .sign
        (nativeX87ReplayAddressing (some .edx) 40)
        zfWritten).registers.get .eax = zfWritten.registers.get .eax
      exact congrArg (fun registers => registers.get .eax)
        (nativeX87ReplaySetConditionMemoryState_registers .sign
          (nativeX87ReplayAddressing (some .edx) 40) zfWritten)
    _ = pfWritten.registers.get .eax := by
      change (nativeX87ReplaySetConditionMemoryState .equal
        (nativeX87ReplayAddressing (some .edx) 36)
        pfWritten).registers.get .eax = pfWritten.registers.get .eax
      exact congrArg (fun registers => registers.get .eax)
        (nativeX87ReplaySetConditionMemoryState_registers .equal
          (nativeX87ReplayAddressing (some .edx) 36) pfWritten)
    _ = cfWritten.registers.get .eax := by
      change (nativeX87ReplaySetConditionMemoryState .parity
        (nativeX87ReplayAddressing (some .edx) 48)
        cfWritten).registers.get .eax = cfWritten.registers.get .eax
      exact congrArg (fun registers => registers.get .eax)
        (nativeX87ReplaySetConditionMemoryState_registers .parity
          (nativeX87ReplayAddressing (some .edx) 48) cfWritten)
    _ = eaxWritten.registers.get .eax := by
      change (nativeX87ReplaySetConditionMemoryState .below
        (nativeX87ReplayAddressing (some .edx) 32)
        eaxWritten).registers.get .eax = eaxWritten.registers.get .eax
      exact congrArg (fun registers => registers.get .eax)
        (nativeX87ReplaySetConditionMemoryState_registers .below
          (nativeX87ReplayAddressing (some .edx) 32) eaxWritten)
    _ = recovered.registers.get .eax := by
      change (nativeX87ReplayMovToMemoryState
        (nativeX87ReplayAddressing (some .edx) 0) .ecx
        recovered).registers.get .eax = recovered.registers.get .eax
      exact congrArg (fun registers => registers.get .eax)
        (nativeX87ReplayMovToMemoryState_registers
          (nativeX87ReplayAddressing (some .edx) 0) .ecx recovered)
    _ = loaded.registers.get .eax :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .eax
        (nativeX87ReplayMemory (some .esp) 0) loaded (by decide)
    _ = input.registers.get .eax :=
      nativeX87ReplayMovFromOperandState_register_other .edx .eax
        (nativeX87ReplayMemory (some .eax) nativeX87FrameOutputOffset)
        input (by decide)

private structure NativeX87ReplayOutputProjection
    (memory : Memory) (outputAddress : Word)
    (registers : PureState) (eflags : Word) : Prop where
  eax : Memory.read32 memory outputAddress = registers.eax
  carry : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 32) =
    BitVec.ofNat 32 (eflags.extractLsb' 0 1).toNat
  parity : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 48) =
    BitVec.ofNat 32 (eflags.extractLsb' 2 1).toNat
  zero : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 36) =
    BitVec.ofNat 32 (eflags.extractLsb' 6 1).toNat
  sign : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 40) =
    BitVec.ofNat 32 (eflags.extractLsb' 7 1).toNat
  overflow : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 44) =
    BitVec.ofNat 32 (eflags.extractLsb' 11 1).toNat
  eflags : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 240) = eflags

private structure NativeX87ReplayFlagWriteProjection
    (memory : Memory) (outputAddress : Word)
    (registers : PureState) (eflags : Word) : Prop where
  eax : Memory.read32 memory outputAddress = registers.eax
  carry : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 32) =
    BitVec.ofNat 32 (eflags.extractLsb' 0 1).toNat
  parity : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 48) =
    BitVec.ofNat 32 (eflags.extractLsb' 2 1).toNat
  zero : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 36) =
    BitVec.ofNat 32 (eflags.extractLsb' 6 1).toNat
  sign : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 40) =
    BitVec.ofNat 32 (eflags.extractLsb' 7 1).toNat
  overflow : Memory.read32 memory
      (outputAddress + BitVec.ofNat 32 44) =
    BitVec.ofNat 32 (eflags.extractLsb' 11 1).toNat

private theorem nativeX87ReplayFixedTemplateFlagWrittenState_projection
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (inputEflags resultEflags : Word)
    (outputLoaded :
      (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
        input).registers.get .edx = outputAddress)
    (savedEax :
      Memory.read32 input.memory input.registers.esp =
        resultRegisters.eax)
    (inputEflagsExact : input.eflags = resultEflags)
    (carryBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 32) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 0 1).toNat)
    (parityBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 48) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 2 1).toNat)
    (zeroBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 36) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 6 1).toNat)
    (signBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 40) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 7 1).toNat)
    (overflowBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 44) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 11 1).toNat)
    :
    NativeX87ReplayFlagWriteProjection
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
      outputAddress resultRegisters resultEflags := by
  let loaded := nativeX87ReplayFixedTemplateCaptureOutputLoadedState input
  let recovered := nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input
  let eaxWritten := nativeX87ReplayFixedTemplateCaptureEaxWrittenState input
  let cfWritten := nativeX87ReplayFixedTemplateCaptureCfWrittenState input
  let pfWritten := nativeX87ReplayFixedTemplateCapturePfWrittenState input
  let zfWritten := nativeX87ReplayFixedTemplateCaptureZfWrittenState input
  let sfWritten := nativeX87ReplayFixedTemplateCaptureSfWrittenState input
  let ofWritten := nativeX87ReplayFixedTemplateCaptureOfWrittenState input
  have loadedMemory : loaded.memory = input.memory := by
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have loadedEsp : loaded.registers.esp = input.registers.esp := by
    exact nativeX87ReplayMovFromOperandState_register_other .edx .esp
      (nativeX87ReplayMemory (some .eax) nativeX87FrameOutputOffset)
      input (by decide)
  have recoveredMemory : recovered.memory = input.memory := by
    exact (nativeX87ReplayMovFromOperandState_memory _ _ _).trans loadedMemory
  have recoveredEdx : recovered.registers.edx = outputAddress := by
    simpa [Registers.get] using
      (nativeX87ReplayMovFromOperandState_register_other .ecx .edx
        (nativeX87ReplayMemory (some .esp) 0) loaded (by decide)).trans
          outputLoaded
  have recoveredEcx : recovered.registers.get .ecx = resultRegisters.eax := by
    calc
      _ = (readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .esp) 0)).eval loaded :=
        nativeX87ReplayMovFromOperandState_register .ecx
          (nativeX87ReplayMemory (some .esp) 0) loaded
      _ = Memory.read32 loaded.memory
          (loaded.registers.esp + BitVec.ofNat 32 0) :=
        readNativeX87ReplayMemorySome .esp 0 loaded
      _ = Memory.read32 input.memory input.registers.esp := by
        rw [loadedMemory, loadedEsp, BitVec.add_zero]
      _ = resultRegisters.eax := savedEax
  have eaxEdx : eaxWritten.registers.edx = outputAddress := by
    exact (congrArg Registers.edx
      (nativeX87ReplayMovToMemoryState_registers
        (nativeX87ReplayAddressing (some .edx) 0) .ecx recovered)).trans
          recoveredEdx
  have eaxRead :
      Memory.read32 eaxWritten.memory outputAddress = resultRegisters.eax := by
    simpa only [BitVec.add_zero] using
      (nativeX87ReplayMovToOutputState_read32_same .ecx 0 recovered
        outputAddress recoveredEdx).trans recoveredEcx
  have eaxEflags : eaxWritten.eflags = resultEflags := by
    dsimp [eaxWritten, nativeX87ReplayFixedTemplateCaptureEaxWrittenState,
      recovered, nativeX87ReplayFixedTemplateCaptureEaxRecoveredState,
      loaded, nativeX87ReplayFixedTemplateCaptureOutputLoadedState]
    simp [inputEflagsExact]
  have eaxCarry :
      Memory.read32 eaxWritten.memory
          (outputAddress + BitVec.ofNat 32 32) =
        BitVec.ofNat 32 (inputEflags.extractLsb' 0 1).toNat := by
    calc
      _ = Memory.read32 recovered.memory
          (outputAddress + BitVec.ofNat 32 32) :=
        nativeX87ReplayMovToOutputState_read32_other .ecx 0 32 recovered
          outputAddress recoveredEdx (by decide) (by decide)
          (Or.inl (by decide))
      _ = _ := by rw [recoveredMemory, carryBefore]
  have cfMemory :
      cfWritten.memory =
        eaxWritten.memory.write32
          (outputAddress + BitVec.ofNat 32 32)
          (BitVec.ofNat 32 (resultEflags.extractLsb' 0 1).toNat) := by
    dsimp [cfWritten, nativeX87ReplayFixedTemplateCaptureCfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_memory_below, eaxEdx,
      eaxCarry, eaxEflags,
      replaceEncodedFlagLowByte
        (inputEflags.extractLsb' 0 1) (resultEflags.extractLsb' 0 1)]
    rfl
  have cfEdx : cfWritten.registers.edx = outputAddress := by
    exact (congrArg Registers.edx
      (nativeX87ReplaySetConditionMemoryState_registers .below
        (nativeX87ReplayAddressing (some .edx) 32) eaxWritten)).trans eaxEdx
  have cfEflags : cfWritten.eflags = resultEflags :=
    (nativeX87ReplaySetConditionMemoryState_eflags .below
      (nativeX87ReplayAddressing (some .edx) 32) eaxWritten).trans eaxEflags
  have cfRead :
      Memory.read32 cfWritten.memory
          (outputAddress + BitVec.ofNat 32 32) =
        BitVec.ofNat 32 (resultEflags.extractLsb' 0 1).toNat := by
    rw [cfMemory]
    exact Memory.read32_write32_same _ _ _
  have cfParity :
      Memory.read32 cfWritten.memory
          (outputAddress + BitVec.ofNat 32 48) =
        BitVec.ofNat 32 (inputEflags.extractLsb' 2 1).toNat := by
    rw [cfMemory,
      Memory.read32_write32_translated_of_disjoint eaxWritten.memory
        outputAddress 32 48 _ (by decide) (by decide) (Or.inl (by decide))]
    calc
      _ = Memory.read32 recovered.memory
          (outputAddress + BitVec.ofNat 32 48) :=
        nativeX87ReplayMovToOutputState_read32_other .ecx 0 48 recovered
          outputAddress recoveredEdx (by decide) (by decide)
          (Or.inl (by decide))
      _ = _ := by rw [recoveredMemory, parityBefore]
  have pfMemory :
      pfWritten.memory =
        cfWritten.memory.write32
          (outputAddress + BitVec.ofNat 32 48)
          (BitVec.ofNat 32 (resultEflags.extractLsb' 2 1).toNat) := by
    dsimp [pfWritten, nativeX87ReplayFixedTemplateCapturePfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_memory_parity, cfEdx,
      cfParity, cfEflags,
      replaceEncodedFlagLowByte
        (inputEflags.extractLsb' 2 1) (resultEflags.extractLsb' 2 1)]
    rfl
  have pfEdx : pfWritten.registers.edx = outputAddress := by
    exact (congrArg Registers.edx
      (nativeX87ReplaySetConditionMemoryState_registers .parity
        (nativeX87ReplayAddressing (some .edx) 48) cfWritten)).trans cfEdx
  have pfEflags : pfWritten.eflags = resultEflags :=
    (nativeX87ReplaySetConditionMemoryState_eflags .parity
      (nativeX87ReplayAddressing (some .edx) 48) cfWritten).trans cfEflags
  have pfRead :
      Memory.read32 pfWritten.memory
          (outputAddress + BitVec.ofNat 32 48) =
        BitVec.ofNat 32 (resultEflags.extractLsb' 2 1).toNat := by
    rw [pfMemory]
    exact Memory.read32_write32_same _ _ _
  have pfZero :
      Memory.read32 pfWritten.memory
          (outputAddress + BitVec.ofNat 32 36) =
        BitVec.ofNat 32 (inputEflags.extractLsb' 6 1).toNat := by
    rw [pfMemory,
      Memory.read32_write32_translated_of_disjoint cfWritten.memory
        outputAddress 48 36 _ (by decide) (by decide) (Or.inr (by decide))]
    rw [cfMemory,
      Memory.read32_write32_translated_of_disjoint eaxWritten.memory
        outputAddress 32 36 _ (by decide) (by decide) (Or.inl (by decide))]
    calc
      _ = Memory.read32 recovered.memory
          (outputAddress + BitVec.ofNat 32 36) :=
        nativeX87ReplayMovToOutputState_read32_other .ecx 0 36 recovered
          outputAddress recoveredEdx (by decide) (by decide)
          (Or.inl (by decide))
      _ = _ := by rw [recoveredMemory, zeroBefore]
  have zfMemory :
      zfWritten.memory =
        pfWritten.memory.write32
          (outputAddress + BitVec.ofNat 32 36)
          (BitVec.ofNat 32 (resultEflags.extractLsb' 6 1).toNat) := by
    dsimp [zfWritten, nativeX87ReplayFixedTemplateCaptureZfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_memory_equal, pfEdx,
      pfZero, pfEflags,
      replaceEncodedFlagLowByte
        (inputEflags.extractLsb' 6 1) (resultEflags.extractLsb' 6 1)]
    rfl
  have zfEdx : zfWritten.registers.edx = outputAddress := by
    exact (congrArg Registers.edx
      (nativeX87ReplaySetConditionMemoryState_registers .equal
        (nativeX87ReplayAddressing (some .edx) 36) pfWritten)).trans pfEdx
  have zfEflags : zfWritten.eflags = resultEflags :=
    (nativeX87ReplaySetConditionMemoryState_eflags .equal
      (nativeX87ReplayAddressing (some .edx) 36) pfWritten).trans pfEflags
  have zfRead :
      Memory.read32 zfWritten.memory
          (outputAddress + BitVec.ofNat 32 36) =
        BitVec.ofNat 32 (resultEflags.extractLsb' 6 1).toNat := by
    rw [zfMemory]
    exact Memory.read32_write32_same _ _ _
  have zfSign :
      Memory.read32 zfWritten.memory
          (outputAddress + BitVec.ofNat 32 40) =
        BitVec.ofNat 32 (inputEflags.extractLsb' 7 1).toNat := by
    rw [zfMemory,
      Memory.read32_write32_translated_of_disjoint pfWritten.memory
        outputAddress 36 40 _ (by decide) (by decide) (Or.inl (by decide))]
    rw [pfMemory,
      Memory.read32_write32_translated_of_disjoint cfWritten.memory
        outputAddress 48 40 _ (by decide) (by decide) (Or.inr (by decide))]
    rw [cfMemory,
      Memory.read32_write32_translated_of_disjoint eaxWritten.memory
        outputAddress 32 40 _ (by decide) (by decide) (Or.inl (by decide))]
    calc
      _ = Memory.read32 recovered.memory
          (outputAddress + BitVec.ofNat 32 40) :=
        nativeX87ReplayMovToOutputState_read32_other .ecx 0 40 recovered
          outputAddress recoveredEdx (by decide) (by decide)
          (Or.inl (by decide))
      _ = _ := by rw [recoveredMemory, signBefore]
  have sfMemory :
      sfWritten.memory =
        zfWritten.memory.write32
          (outputAddress + BitVec.ofNat 32 40)
          (BitVec.ofNat 32 (resultEflags.extractLsb' 7 1).toNat) := by
    dsimp [sfWritten, nativeX87ReplayFixedTemplateCaptureSfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_memory_sign, zfEdx,
      zfSign, zfEflags,
      replaceEncodedFlagLowByte
        (inputEflags.extractLsb' 7 1) (resultEflags.extractLsb' 7 1)]
    rfl
  have sfEdx : sfWritten.registers.edx = outputAddress := by
    exact (congrArg Registers.edx
      (nativeX87ReplaySetConditionMemoryState_registers .sign
        (nativeX87ReplayAddressing (some .edx) 40) zfWritten)).trans zfEdx
  have sfEflags : sfWritten.eflags = resultEflags :=
    (nativeX87ReplaySetConditionMemoryState_eflags .sign
      (nativeX87ReplayAddressing (some .edx) 40) zfWritten).trans zfEflags
  have sfRead :
      Memory.read32 sfWritten.memory
          (outputAddress + BitVec.ofNat 32 40) =
        BitVec.ofNat 32 (resultEflags.extractLsb' 7 1).toNat := by
    rw [sfMemory]
    exact Memory.read32_write32_same _ _ _
  have sfOverflow :
      Memory.read32 sfWritten.memory
          (outputAddress + BitVec.ofNat 32 44) =
        BitVec.ofNat 32 (inputEflags.extractLsb' 11 1).toNat := by
    rw [sfMemory,
      Memory.read32_write32_translated_of_disjoint zfWritten.memory
        outputAddress 40 44 _ (by decide) (by decide) (Or.inl (by decide))]
    rw [zfMemory,
      Memory.read32_write32_translated_of_disjoint pfWritten.memory
        outputAddress 36 44 _ (by decide) (by decide) (Or.inl (by decide))]
    rw [pfMemory,
      Memory.read32_write32_translated_of_disjoint cfWritten.memory
        outputAddress 48 44 _ (by decide) (by decide) (Or.inr (by decide))]
    rw [cfMemory,
      Memory.read32_write32_translated_of_disjoint eaxWritten.memory
        outputAddress 32 44 _ (by decide) (by decide) (Or.inl (by decide))]
    calc
      _ = Memory.read32 recovered.memory
          (outputAddress + BitVec.ofNat 32 44) :=
        nativeX87ReplayMovToOutputState_read32_other .ecx 0 44 recovered
          outputAddress recoveredEdx (by decide) (by decide)
          (Or.inl (by decide))
      _ = _ := by rw [recoveredMemory, overflowBefore]
  have ofMemory :
      ofWritten.memory =
        sfWritten.memory.write32
          (outputAddress + BitVec.ofNat 32 44)
          (BitVec.ofNat 32 (resultEflags.extractLsb' 11 1).toNat) := by
    dsimp [ofWritten, nativeX87ReplayFixedTemplateCaptureOfWrittenState]
    rw [nativeX87ReplaySetConditionMemoryState_memory_overflow, sfEdx,
      sfOverflow, sfEflags,
      replaceEncodedFlagLowByte
        (inputEflags.extractLsb' 11 1) (resultEflags.extractLsb' 11 1)]
    rfl
  have ofEdx : ofWritten.registers.edx = outputAddress := by
    exact (congrArg Registers.edx
      (nativeX87ReplaySetConditionMemoryState_registers .overflow
        (nativeX87ReplayAddressing (some .edx) 44) sfWritten)).trans sfEdx
  have ofRead :
      Memory.read32 ofWritten.memory
          (outputAddress + BitVec.ofNat 32 44) =
        BitVec.ofNat 32 (resultEflags.extractLsb' 11 1).toNat := by
    rw [ofMemory]
    exact Memory.read32_write32_same _ _ _
  change NativeX87ReplayFlagWriteProjection ofWritten.memory outputAddress
    resultRegisters resultEflags
  refine {
    eax := ?_
    carry := ?_
    parity := ?_
    zero := ?_
    sign := ?_
    overflow := ?_
  }
  · have eaxAtZero :
        Memory.read32 ofWritten.memory
            (outputAddress + BitVec.ofNat 32 0) =
          resultRegisters.eax := by
      rw [ofMemory,
        Memory.read32_write32_translated_of_disjoint sfWritten.memory
          outputAddress 44 0 _ (by decide) (by decide) (Or.inr (by decide)),
        sfMemory,
        Memory.read32_write32_translated_of_disjoint zfWritten.memory
          outputAddress 40 0 _ (by decide) (by decide) (Or.inr (by decide)),
        zfMemory,
        Memory.read32_write32_translated_of_disjoint pfWritten.memory
          outputAddress 36 0 _ (by decide) (by decide) (Or.inr (by decide)),
        pfMemory,
        Memory.read32_write32_translated_of_disjoint cfWritten.memory
          outputAddress 48 0 _ (by decide) (by decide) (Or.inr (by decide)),
        cfMemory,
        Memory.read32_write32_translated_of_disjoint eaxWritten.memory
          outputAddress 32 0 _ (by decide) (by decide) (Or.inr (by decide))]
      simpa only [BitVec.add_zero] using eaxRead
    simpa only [BitVec.add_zero] using eaxAtZero
  · rw [ofMemory,
      Memory.read32_write32_translated_of_disjoint sfWritten.memory
        outputAddress 44 32 _ (by decide) (by decide) (Or.inr (by decide)),
      sfMemory,
      Memory.read32_write32_translated_of_disjoint zfWritten.memory
        outputAddress 40 32 _ (by decide) (by decide) (Or.inr (by decide)),
      zfMemory,
      Memory.read32_write32_translated_of_disjoint pfWritten.memory
        outputAddress 36 32 _ (by decide) (by decide) (Or.inr (by decide)),
      pfMemory,
      Memory.read32_write32_translated_of_disjoint cfWritten.memory
        outputAddress 48 32 _ (by decide) (by decide) (Or.inr (by decide))]
    exact cfRead
  · rw [ofMemory,
      Memory.read32_write32_translated_of_disjoint sfWritten.memory
        outputAddress 44 48 _ (by decide) (by decide) (Or.inl (by decide)),
      sfMemory,
      Memory.read32_write32_translated_of_disjoint zfWritten.memory
        outputAddress 40 48 _ (by decide) (by decide) (Or.inl (by decide)),
      zfMemory,
      Memory.read32_write32_translated_of_disjoint pfWritten.memory
        outputAddress 36 48 _ (by decide) (by decide) (Or.inl (by decide))]
    exact pfRead
  · rw [ofMemory,
      Memory.read32_write32_translated_of_disjoint sfWritten.memory
        outputAddress 44 36 _ (by decide) (by decide) (Or.inr (by decide)),
      sfMemory,
      Memory.read32_write32_translated_of_disjoint zfWritten.memory
        outputAddress 40 36 _ (by decide) (by decide) (Or.inr (by decide))]
    exact zfRead
  · rw [ofMemory,
      Memory.read32_write32_translated_of_disjoint sfWritten.memory
        outputAddress 44 40 _ (by decide) (by decide) (Or.inr (by decide))]
    exact sfRead
  · exact ofRead

private theorem nativeX87ReplayFixedTemplateCaptureOfWrittenState_edx
    (input : MachineState) (outputAddress : Word)
    (outputLoaded :
      (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
        input).registers.get .edx = outputAddress) :
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState
      input).registers.get .edx = outputAddress := by
  let loaded := nativeX87ReplayFixedTemplateCaptureOutputLoadedState input
  let recovered := nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input
  let eaxWritten := nativeX87ReplayFixedTemplateCaptureEaxWrittenState input
  let cfWritten := nativeX87ReplayFixedTemplateCaptureCfWrittenState input
  let pfWritten := nativeX87ReplayFixedTemplateCapturePfWrittenState input
  let zfWritten := nativeX87ReplayFixedTemplateCaptureZfWrittenState input
  let sfWritten := nativeX87ReplayFixedTemplateCaptureSfWrittenState input
  calc
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx =
        sfWritten.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCaptureOfWrittenState,
        sfWritten] using
        congrArg (fun registers => registers.get .edx)
          (nativeX87ReplaySetConditionMemoryState_registers .overflow
            (nativeX87ReplayAddressing (some .edx) 44) sfWritten)
    _ = zfWritten.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCaptureSfWrittenState,
        zfWritten] using
        congrArg (fun registers => registers.get .edx)
          (nativeX87ReplaySetConditionMemoryState_registers .sign
            (nativeX87ReplayAddressing (some .edx) 40) zfWritten)
    _ = pfWritten.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCaptureZfWrittenState,
        pfWritten] using
        congrArg (fun registers => registers.get .edx)
          (nativeX87ReplaySetConditionMemoryState_registers .equal
            (nativeX87ReplayAddressing (some .edx) 36) pfWritten)
    _ = cfWritten.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCapturePfWrittenState,
        cfWritten] using
        congrArg (fun registers => registers.get .edx)
          (nativeX87ReplaySetConditionMemoryState_registers .parity
            (nativeX87ReplayAddressing (some .edx) 48) cfWritten)
    _ = eaxWritten.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCaptureCfWrittenState,
        eaxWritten] using
        congrArg (fun registers => registers.get .edx)
          (nativeX87ReplaySetConditionMemoryState_registers .below
            (nativeX87ReplayAddressing (some .edx) 32) eaxWritten)
    _ = recovered.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCaptureEaxWrittenState,
        recovered] using
        congrArg (fun registers => registers.get .edx)
          (nativeX87ReplayMovToMemoryState_registers
            (nativeX87ReplayAddressing (some .edx) 0) .ecx recovered)
    _ = loaded.registers.get .edx :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .edx
        (nativeX87ReplayMemory (some .esp) 0) loaded (by decide)
    _ = outputAddress := outputLoaded

private theorem
    nativeX87ReplayFixedTemplateCaptureOfWrittenState_register_other
    (input : MachineState) (register : Reg)
    (notEdx : register ≠ .edx) (notEcx : register ≠ .ecx) :
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState
      input).registers.get register =
      input.registers.get register := by
  let loaded := nativeX87ReplayFixedTemplateCaptureOutputLoadedState input
  let recovered := nativeX87ReplayFixedTemplateCaptureEaxRecoveredState input
  let eaxWritten := nativeX87ReplayFixedTemplateCaptureEaxWrittenState input
  let cfWritten := nativeX87ReplayFixedTemplateCaptureCfWrittenState input
  let pfWritten := nativeX87ReplayFixedTemplateCapturePfWrittenState input
  let zfWritten := nativeX87ReplayFixedTemplateCaptureZfWrittenState input
  let sfWritten := nativeX87ReplayFixedTemplateCaptureSfWrittenState input
  calc
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get register =
        sfWritten.registers.get register := by
      simpa only [nativeX87ReplayFixedTemplateCaptureOfWrittenState,
        sfWritten] using
        congrArg (fun registers => registers.get register)
          (nativeX87ReplaySetConditionMemoryState_registers .overflow
            (nativeX87ReplayAddressing (some .edx) 44) sfWritten)
    _ = zfWritten.registers.get register := by
      simpa only [nativeX87ReplayFixedTemplateCaptureSfWrittenState,
        zfWritten] using
        congrArg (fun registers => registers.get register)
          (nativeX87ReplaySetConditionMemoryState_registers .sign
            (nativeX87ReplayAddressing (some .edx) 40) zfWritten)
    _ = pfWritten.registers.get register := by
      simpa only [nativeX87ReplayFixedTemplateCaptureZfWrittenState,
        pfWritten] using
        congrArg (fun registers => registers.get register)
          (nativeX87ReplaySetConditionMemoryState_registers .equal
            (nativeX87ReplayAddressing (some .edx) 36) pfWritten)
    _ = cfWritten.registers.get register := by
      simpa only [nativeX87ReplayFixedTemplateCapturePfWrittenState,
        cfWritten] using
        congrArg (fun registers => registers.get register)
          (nativeX87ReplaySetConditionMemoryState_registers .parity
            (nativeX87ReplayAddressing (some .edx) 48) cfWritten)
    _ = eaxWritten.registers.get register := by
      simpa only [nativeX87ReplayFixedTemplateCaptureCfWrittenState,
        eaxWritten] using
        congrArg (fun registers => registers.get register)
          (nativeX87ReplaySetConditionMemoryState_registers .below
            (nativeX87ReplayAddressing (some .edx) 32) eaxWritten)
    _ = recovered.registers.get register := by
      simpa only [nativeX87ReplayFixedTemplateCaptureEaxWrittenState,
        recovered] using
        congrArg (fun registers => registers.get register)
          (nativeX87ReplayMovToMemoryState_registers
            (nativeX87ReplayAddressing (some .edx) 0) .ecx recovered)
    _ = loaded.registers.get register :=
      nativeX87ReplayMovFromOperandState_register_other .ecx register
        (nativeX87ReplayMemory (some .esp) 0) loaded notEcx
    _ = input.registers.get register :=
      nativeX87ReplayMovFromOperandState_register_other .edx register
        (nativeX87ReplayMemory (some .eax) nativeX87FrameOutputOffset)
        input notEdx

private theorem nativeX87ReplayFixedTemplateCaptureMergedFlagsState_memory
    (undefinedSlot : Nat) (input : MachineState) :
    (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
      input).memory =
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory := by
  simp only [nativeX87ReplayFixedTemplateCaptureMergedFlagsState,
    nativeX87ReplayFixedTemplateCaptureResultFlagsState,
    nativeX87ReplayFixedTemplateCapturePreservedFlagsState,
    nativeX87ReplayFixedTemplateCaptureInputFlagsState,
    nativeX87ReplayFixedTemplateCaptureInputLoadedState,
    nativeX87ReplayFixedTemplateCaptureSavedFlagsState,
    nativeX87ReplayOrRegisterState_memory,
    nativeX87ReplayAndRegisterState_memory,
    nativeX87ReplayMovFromOperandState_memory]

private theorem nativeX87ReplayFixedTemplateCaptureMergedFlagsState_edx
    (undefinedSlot : Nat) (input : MachineState) (outputAddress : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress) :
    (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
      input).registers.get .edx = outputAddress := by
  let ofWritten := nativeX87ReplayFixedTemplateCaptureOfWrittenState input
  let savedFlags := nativeX87ReplayFixedTemplateCaptureSavedFlagsState input
  let inputLoaded := nativeX87ReplayFixedTemplateCaptureInputLoadedState input
  let inputFlags := nativeX87ReplayFixedTemplateCaptureInputFlagsState input
  let preserved :=
    nativeX87ReplayFixedTemplateCapturePreservedFlagsState undefinedSlot input
  let result :=
    nativeX87ReplayFixedTemplateCaptureResultFlagsState undefinedSlot input
  calc
    (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
        input).registers.get .edx =
        result.registers.get .edx := by
      simpa only [nativeX87ReplayFixedTemplateCaptureMergedFlagsState,
        result] using
        nativeX87ReplayOrRegisterState_register_other
          (undefinedSlot + 17) .ecx .edx (.register .ebx) result (by decide)
    _ = preserved.registers.get .edx :=
      nativeX87ReplayAndRegisterState_register_other
        (undefinedSlot + 16) .ebx .edx (.immediate 0x0cd5) preserved
        (by decide)
    _ = inputFlags.registers.get .edx :=
      nativeX87ReplayAndRegisterState_register_other
        (undefinedSlot + 15) .ecx .edx (.immediate 0xfffff32a) inputFlags
        (by decide)
    _ = inputLoaded.registers.get .edx :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .edx
        (nativeX87ReplayMemory (some .ecx) 240) inputLoaded (by decide)
    _ = savedFlags.registers.get .edx :=
      nativeX87ReplayMovFromOperandState_register_other .ecx .edx
        (nativeX87ReplayMemory (some .eax) nativeX87FrameInputOffset)
        savedFlags (by decide)
    _ = ofWritten.registers.get .edx :=
      nativeX87ReplayMovFromOperandState_register_other .ebx .edx
        (nativeX87ReplayMemory (some .esp) 4) ofWritten (by decide)
    _ = outputAddress := ofEdx

private theorem
    nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (offset : Nat)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (beforeFinalWrite : offset + 4 <= 240) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 offset) =
      Memory.read32
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        (outputAddress + BitVec.ofNat 32 offset) := by
  let merged :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot input
  have mergedMemory :
      merged.memory =
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState_memory undefinedSlot
      input
  have mergedEdx : merged.registers.get .edx = outputAddress :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState_edx undefinedSlot input
      outputAddress ofEdx
  exact
    (nativeX87ReplayMovToOutputState_read32_other .ecx 240 offset merged
      outputAddress mergedEdx (by decide) (by omega)
      (Or.inr beforeFinalWrite)).trans
      (congrArg
        (fun memory => Memory.read32 memory
          (outputAddress + BitVec.ofNat 32 offset))
        mergedMemory)

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_eax_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        outputAddress =
      resultRegisters.eax := by
  simpa only [BitVec.add_zero] using
    (nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
      undefinedSlot frameAddress outputAddress input 0 ofEdx
      (by decide)).trans
      (by simpa only [BitVec.add_zero] using flags.eax)

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_carry_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 32) =
      BitVec.ofNat 32 (resultEflags.extractLsb' 0 1).toNat :=
  (nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
    undefinedSlot frameAddress outputAddress input 32 ofEdx
    (by decide)).trans flags.carry

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_parity_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 48) =
      BitVec.ofNat 32 (resultEflags.extractLsb' 2 1).toNat :=
  (nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
    undefinedSlot frameAddress outputAddress input 48 ofEdx
    (by decide)).trans flags.parity

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_zero_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 36) =
      BitVec.ofNat 32 (resultEflags.extractLsb' 6 1).toNat :=
  (nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
    undefinedSlot frameAddress outputAddress input 36 ofEdx
    (by decide)).trans flags.zero

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_sign_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 40) =
      BitVec.ofNat 32 (resultEflags.extractLsb' 7 1).toNat :=
  (nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
    undefinedSlot frameAddress outputAddress input 40 ofEdx
    (by decide)).trans flags.sign

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_overflow_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 44) =
      BitVec.ofNat 32 (resultEflags.extractLsb' 11 1).toNat :=
  (nativeX87ReplayFixedTemplateOutputWrittenState_read32_before_final_write
    undefinedSlot frameAddress outputAddress input 44 ofEdx
    (by decide)).trans flags.overflow

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_eflags_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags)
    (mergedEflags :
      (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
        input).registers.get .ecx = resultEflags) :
    Memory.read32
        (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
          frameAddress input).memory
        (outputAddress + BitVec.ofNat 32 240) =
      resultEflags := by
  let merged :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot input
  have mergedEdx : merged.registers.get .edx = outputAddress :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState_edx undefinedSlot input
      outputAddress ofEdx
  exact (nativeX87ReplayMovToOutputState_read32_same .ecx 240 merged
    outputAddress mergedEdx).trans mergedEflags

private theorem
    nativeX87ReplayFixedTemplateOutputWrittenState_projection_of_flags
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (resultEflags : Word)
    (ofEdx :
      (nativeX87ReplayFixedTemplateCaptureOfWrittenState
        input).registers.get .edx = outputAddress)
    (flags :
      NativeX87ReplayFlagWriteProjection
        (nativeX87ReplayFixedTemplateCaptureOfWrittenState input).memory
        outputAddress resultRegisters resultEflags)
    (mergedEflags :
      (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
        input).registers.get .ecx = resultEflags) :
    NativeX87ReplayOutputProjection
      (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
        frameAddress input).memory
      outputAddress resultRegisters resultEflags := by
  exact {
    eax :=
      nativeX87ReplayFixedTemplateOutputWrittenState_eax_of_flags undefinedSlot
        frameAddress outputAddress input resultRegisters resultEflags ofEdx flags
    carry :=
      nativeX87ReplayFixedTemplateOutputWrittenState_carry_of_flags
        undefinedSlot frameAddress outputAddress input resultRegisters
        resultEflags ofEdx flags
    parity :=
      nativeX87ReplayFixedTemplateOutputWrittenState_parity_of_flags
        undefinedSlot frameAddress outputAddress input resultRegisters
        resultEflags ofEdx flags
    zero :=
      nativeX87ReplayFixedTemplateOutputWrittenState_zero_of_flags undefinedSlot
        frameAddress outputAddress input resultRegisters resultEflags ofEdx flags
    sign :=
      nativeX87ReplayFixedTemplateOutputWrittenState_sign_of_flags undefinedSlot
        frameAddress outputAddress input resultRegisters resultEflags ofEdx flags
    overflow :=
      nativeX87ReplayFixedTemplateOutputWrittenState_overflow_of_flags
        undefinedSlot frameAddress outputAddress input resultRegisters
        resultEflags ofEdx flags
    eflags :=
      nativeX87ReplayFixedTemplateOutputWrittenState_eflags_of_flags
        undefinedSlot frameAddress outputAddress input resultRegisters
        resultEflags ofEdx flags mergedEflags
  }

private theorem nativeX87ReplayFixedTemplateOutputWrittenState_projection
    (undefinedSlot : Nat) (frameAddress outputAddress : Word)
    (input : MachineState) (resultRegisters : PureState)
    (inputEflags resultEflags : Word)
    (outputLoaded :
      (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
        input).registers.get .edx = outputAddress)
    (savedEax :
      Memory.read32 input.memory input.registers.esp =
        resultRegisters.eax)
    (inputEflagsExact : input.eflags = resultEflags)
    (carryBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 32) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 0 1).toNat)
    (parityBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 48) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 2 1).toNat)
    (zeroBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 36) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 6 1).toNat)
    (signBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 40) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 7 1).toNat)
    (overflowBefore : Memory.read32 input.memory
        (outputAddress + BitVec.ofNat 32 44) =
      BitVec.ofNat 32 (inputEflags.extractLsb' 11 1).toNat)
    (mergedEflags :
      (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
        input).registers.get .ecx = resultEflags) :
    NativeX87ReplayOutputProjection
      (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
        frameAddress input).memory
      outputAddress resultRegisters resultEflags :=
  nativeX87ReplayFixedTemplateOutputWrittenState_projection_of_flags
    undefinedSlot frameAddress outputAddress input resultRegisters resultEflags
    (nativeX87ReplayFixedTemplateCaptureOfWrittenState_edx input outputAddress
      outputLoaded)
    (nativeX87ReplayFixedTemplateFlagWrittenState_projection undefinedSlot
      frameAddress outputAddress input resultRegisters inputEflags resultEflags
      outputLoaded savedEax inputEflagsExact carryBefore parityBefore zeroBefore
      signBefore overflowBefore)
    mergedEflags

private def nativeX87ReplayFixedTemplateCapturePoppedState
    (input : MachineState) : MachineState :=
  let direction := nativeX87ReplayClearDirectionState input
  let edi := nativeX87ReplayPopRegState .edi direction
  let esi := nativeX87ReplayPopRegState .esi edi
  let ebx := nativeX87ReplayPopRegState .ebx esi
  nativeX87ReplayPopRegState .ebp ebx

@[simp] private theorem nativeX87ReplayFixedTemplateCapturePoppedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateCapturePoppedState input).memory =
      input.memory := by
  unfold nativeX87ReplayFixedTemplateCapturePoppedState
  simp only [nativeX87ReplayPopRegState_memory,
    nativeX87ReplayClearDirectionState_memory]

private def nativeX87ReplayFixedTemplateCaptureReturnEntryState
    (frameAddress : Word) (input : MachineState) : MachineState :=
  let padded := nativeX87ReplayNopState 10 input
  let status := nativeX87ReplayMovImmediateMemoryState
    (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset) 0 padded
  let privateStack := nativeX87ReplayMovFromOperandState .esp
    (nativeX87ReplayMemory (some .eax) nativeX87FramePrivateEspOffset) status
  let direction := nativeX87ReplayClearDirectionState privateStack
  let edi := nativeX87ReplayPopRegState .edi direction
  let esi := nativeX87ReplayPopRegState .esi edi
  let ebx := nativeX87ReplayPopRegState .ebx esi
  nativeX87ReplayPopRegState .ebp ebx

private theorem nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory
    (frameAddress : Word) (input : MachineState)
    (eaxExact : input.registers.get .eax = frameAddress) :
    (nativeX87ReplayFixedTemplateCaptureReturnEntryState frameAddress
      input).memory =
      input.memory.write32
        (frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset)
        (BitVec.ofNat 32 0) := by
  let padded := nativeX87ReplayNopState 10 input
  have paddedEax : padded.registers.get .eax = frameAddress := by
    dsimp [padded]
    rw [nativeX87ReplayNopState_registers]
    exact eaxExact
  unfold nativeX87ReplayFixedTemplateCaptureReturnEntryState
  simp only [nativeX87ReplayPopRegState_memory,
    nativeX87ReplayClearDirectionState_memory,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayMovImmediateMemoryState_memory,
    nativeX87ReplayAddressing_some_eval]
  rw [paddedEax, nativeX87ReplayNopState_memory]

private theorem nativeX87ReplayFixedTemplateCaptureReturnEntryState_status
    (frameAddress : Word) (input : MachineState)
    (eaxExact : input.registers.get .eax = frameAddress) :
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureReturnEntryState frameAddress
          input).memory
        (frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) =
      BitVec.ofNat 32 0 := by
  rw [nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory frameAddress
    input eaxExact]
  exact Memory.read32_write32_same _ _ _

private theorem nativeX87ReplayFixedTemplateCaptureStatusState_memory
    (frameAddress : Word) (input : MachineState)
    (eaxExact : input.registers.get .eax = frameAddress) :
    let padded := nativeX87ReplayNopState 10 input
    let status := nativeX87ReplayMovImmediateMemoryState
      (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset) 0 padded
    status.memory =
      input.memory.write32
        (frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset)
        (BitVec.ofNat 32 0) := by
  dsimp only
  let padded := nativeX87ReplayNopState 10 input
  have paddedEax : padded.registers.get .eax = frameAddress := by
    exact (congrArg (fun registers => registers.get .eax)
      (nativeX87ReplayNopState_registers 10 input)).trans eaxExact
  rw [nativeX87ReplayMovImmediateMemoryState_memory,
    nativeX87ReplayAddressing_some_eval, paddedEax,
    nativeX87ReplayNopState_memory]

private theorem
    nativeX87ReplayFixedTemplateCaptureStatusState_privateStackPointer
    (frameAddress privateStackPointer : Word) (input : MachineState)
    (eaxExact : input.registers.get .eax = frameAddress)
    (privateStackExact :
      Memory.read32 input.memory
          (frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
        privateStackPointer) :
    let padded := nativeX87ReplayNopState 10 input
    let status := nativeX87ReplayMovImmediateMemoryState
      (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset) 0 padded
    Memory.read32 status.memory
        (frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
      privateStackPointer := by
  dsimp only
  rw [nativeX87ReplayFixedTemplateCaptureStatusState_memory
    frameAddress input eaxExact]
  exact (Memory.read32_write32_translated_of_disjoint input.memory
    frameAddress nativeX87FrameStatusOffset nativeX87FramePrivateEspOffset
    (BitVec.ofNat 32 0) (by decide) (by decide)
    (Or.inr (by decide))).trans privateStackExact

private theorem nativeX87ReplayFixedTemplateCapturePrivateStackState_esp
    (frameAddress privateStackPointer : Word) (input : MachineState)
    (eaxExact : input.registers.get .eax = frameAddress)
    (privateStackExact :
      Memory.read32 input.memory
          (frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
        privateStackPointer) :
    let padded := nativeX87ReplayNopState 10 input
    let status := nativeX87ReplayMovImmediateMemoryState
      (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset) 0 padded
    let privateStack := nativeX87ReplayMovFromOperandState .esp
      (nativeX87ReplayMemory (some .eax) nativeX87FramePrivateEspOffset) status
    privateStack.registers.esp = privateStackPointer := by
  dsimp only
  let padded := nativeX87ReplayNopState 10 input
  let status := nativeX87ReplayMovImmediateMemoryState
    (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset) 0 padded
  have paddedEax : padded.registers.get .eax = frameAddress := by
    exact (congrArg (fun registers => registers.get .eax)
      (nativeX87ReplayNopState_registers 10 input)).trans eaxExact
  have statusEax : status.registers.get .eax = frameAddress := by
    exact (congrArg (fun registers => registers.get .eax)
      (nativeX87ReplayMovImmediateMemoryState_registers
        (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset)
        0 padded)).trans paddedEax
  have statusPrivateStack :
      Memory.read32 status.memory
          (frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
        privateStackPointer :=
    nativeX87ReplayFixedTemplateCaptureStatusState_privateStackPointer
      frameAddress privateStackPointer input eaxExact privateStackExact
  change (nativeX87ReplayMovFromOperandState .esp
      (nativeX87ReplayMemory (some .eax) nativeX87FramePrivateEspOffset)
      status).registers.get .esp = privateStackPointer
  rw [nativeX87ReplayMovFromOperandState_register,
    readNativeX87ReplayMemorySome, statusEax, statusPrivateStack]

private theorem nativeX87ReplayFixedTemplateCapturePoppedState_esp
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateCapturePoppedState input).registers.esp =
      input.registers.esp + BitVec.ofNat 32 16 := by
  let direction := nativeX87ReplayClearDirectionState input
  let edi := nativeX87ReplayPopRegState .edi direction
  let esi := nativeX87ReplayPopRegState .esi edi
  let ebx := nativeX87ReplayPopRegState .ebx esi
  have directionEsp :
      direction.registers.esp = input.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayClearDirectionState_registers input)
  calc
    (nativeX87ReplayFixedTemplateCapturePoppedState input).registers.esp =
        ebx.registers.esp + BitVec.ofNat 32 4 :=
      nativeX87ReplayPopRegState_esp .ebp ebx
    _ = (esi.registers.esp + BitVec.ofNat 32 4) +
        BitVec.ofNat 32 4 := congrArg
      (fun value => value + BitVec.ofNat 32 4)
      (nativeX87ReplayPopRegState_esp .ebx esi)
    _ = ((edi.registers.esp + BitVec.ofNat 32 4) +
          BitVec.ofNat 32 4) + BitVec.ofNat 32 4 := congrArg
      (fun value => (value + BitVec.ofNat 32 4) + BitVec.ofNat 32 4)
      (nativeX87ReplayPopRegState_esp .esi edi)
    _ = (((direction.registers.esp + BitVec.ofNat 32 4) +
          BitVec.ofNat 32 4) + BitVec.ofNat 32 4) +
          BitVec.ofNat 32 4 := congrArg
      (fun value => ((value + BitVec.ofNat 32 4) +
        BitVec.ofNat 32 4) + BitVec.ofNat 32 4)
      (nativeX87ReplayPopRegState_esp .edi direction)
    _ = (((input.registers.esp + BitVec.ofNat 32 4) +
          BitVec.ofNat 32 4) + BitVec.ofNat 32 4) +
          BitVec.ofNat 32 4 := congrArg
      (fun value => (((value + BitVec.ofNat 32 4) +
        BitVec.ofNat 32 4) + BitVec.ofNat 32 4) +
        BitVec.ofNat 32 4) directionEsp
    _ = input.registers.esp + BitVec.ofNat 32 16 := by
      simp [BitVec.add_assoc, ← BitVec.ofNat_add]

private theorem nativeX87ReplayFixedTemplateCaptureReturnEntryState_esp
    (frameAddress privateStackPointer : Word) (input : MachineState)
    (eaxExact : input.registers.get .eax = frameAddress)
    (privateStackExact :
      Memory.read32 input.memory
          (frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
        privateStackPointer) :
    (nativeX87ReplayFixedTemplateCaptureReturnEntryState frameAddress
      input).registers.esp =
      privateStackPointer + BitVec.ofNat 32 16 := by
  let padded := nativeX87ReplayNopState 10 input
  let status := nativeX87ReplayMovImmediateMemoryState
    (nativeX87ReplayAddressing (some .eax) nativeX87FrameStatusOffset) 0 padded
  let privateStack := nativeX87ReplayMovFromOperandState .esp
    (nativeX87ReplayMemory (some .eax) nativeX87FramePrivateEspOffset) status
  have privateStackEsp :
      privateStack.registers.esp = privateStackPointer :=
    nativeX87ReplayFixedTemplateCapturePrivateStackState_esp
      frameAddress privateStackPointer input eaxExact privateStackExact
  calc
    (nativeX87ReplayFixedTemplateCaptureReturnEntryState frameAddress
        input).registers.esp =
      (nativeX87ReplayFixedTemplateCapturePoppedState
        privateStack).registers.esp := rfl
    _ = privateStack.registers.esp + BitVec.ofNat 32 16 :=
      nativeX87ReplayFixedTemplateCapturePoppedState_esp privateStack
    _ = privateStackPointer + BitVec.ofNat 32 16 := by rw [privateStackEsp]

private def nativeX87ReplayFixedTemplateCaptureFinalState
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (undefinedSlot : Nat) (frameAddress : Word)
    (input : MachineState) : MachineState :=
  nativeX87ReplayFixedTemplateCaptureReturnEntryState frameAddress
    (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot frameAddress
      (nativeX87ReplayFixedTemplateCaptureSavedState table pe frameAddress input))

private theorem nativeX87ReplayFixedTemplateCaptureReturnRva
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    runtimeTarget.target.frameMapping.returnRva =
      runtimeTarget.target.frameMapping.captureRva + 99 := by
  by_cases exact :
      runtimeTarget.target.frameMapping.returnRva =
        runtimeTarget.target.frameMapping.captureRva + 99
  · exact exact
  · have checked := runtimeTarget.target.frameMappingChecked
    simp [NativeX87ReplayBridgeFrameMapping.checked, exact,
      nativeX87ReplayBridgeCaptureOffset,
      nativeX87ReplayBridgeReturnOffset] at checked
    omega

private theorem nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (frameAddress : Word) (input : MachineState)
    (active :
      Memory.read32
          (nativeX87ReplayPushRegState .eax
            (nativeX87ReplayPushFlagsState input)).memory
          (BitVec.ofNat 32
            ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
        frameAddress) :
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
      input).registers.eax = frameAddress := by
  unfold nativeX87ReplayFixedTemplateCaptureBeforeSaveState
  change (nativeX87ReplayMovFromOperandState .eax
    (nativeX87ReplayMemory none
      ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)))
    (nativeX87ReplayPushRegState .eax
      (nativeX87ReplayPushFlagsState input))).registers.get .eax = frameAddress
  rw [nativeX87ReplayMovFromOperandState_register]
  rw [readNativeX87ReplayMemoryNone]
  exact active

private theorem nativeX87ReplayFixedTemplateCaptureBeforeSaveState_x87Physical
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
      input).x87Physical = input.x87Physical := by
  unfold nativeX87ReplayFixedTemplateCaptureBeforeSaveState
  rw [nativeX87ReplayMovFromOperandState_x87Physical,
    nativeX87ReplayPushRegState_x87Physical]
  exact nativeX87ReplayOrdinaryState_x87Physical
    nativeX87ReplayPushFlagsBehavior input

private theorem nativeX87ReplayFixedTemplateCaptureRoles_running
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (undefinedSlot : Nat) (frameAddress : Word) (input : MachineState)
    (active :
      Memory.read32
          (nativeX87ReplayPushRegState .eax
            (nativeX87ReplayPushFlagsState input)).memory
          (BitVec.ofNat 32
            ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
        frameAddress)
    (outputValid :
      kernelX87FrameAddressValid
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset) = true) :
    runNativeX87ReplayTemplateRoles pe imports undefinedSlot input
        (nativeX87ReplayFixedTemplateCaptureRoles table pe
          runtimeTarget.target.frameMapping) =
      .running runtimeTarget.target.frameMapping.returnRva
        (undefinedSlot +
          (nativeX87ReplayFixedTemplateCaptureRoles table pe
            runtimeTarget.target.frameMapping).length)
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          frameAddress input) := by
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input
  have beforeSaveEax : beforeSave.registers.eax = frameAddress := by
    exact nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax table pe
      frameAddress input active
  have fnSaveExact :
      (NativeX87ReplayTemplateRole.x87Frame
        (runtimeTarget.target.frameMapping.captureRva + 7) {
          operation := .fnSave
          addressing := nativeX87ReplayAddressing (some .eax) 128
          size := 6
        }).semanticStep pe imports (undefinedSlot + 3) beforeSave =
      .running (runtimeTarget.target.frameMapping.captureRva + 13)
        (undefinedSlot + 4)
        (nativeX87ReplayFixedTemplateCaptureSavedState table pe frameAddress
          input) := by
    apply NativeX87ReplayTemplateRole.semanticStep_fnSave
      (address :=
        frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
    · unfold kernelX87FrameAddress
      rw [nativeX87ReplayAddressing_some_eval]
      change beforeSave.registers.get .eax = frameAddress at beforeSaveEax
      rw [beforeSaveEax]
      rfl
    · exact outputValid
  simp only [nativeX87ReplayFixedTemplateCaptureRoles, List.append_assoc,
    List.cons_append, List.nil_append, nativeX87ReplayOrdinaryRole,
    nativeX87ReplayMemory, nativeX87ReplayByteMemory,
    nativeX87ReplayNopRoles]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushFlags
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushReg
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  change runNativeX87ReplayTemplateRoles pe imports (undefinedSlot + 3)
      beforeSave _ = _
  rw [runNativeX87ReplayTemplateRoles_cons_running fnSaveExact
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movToMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_setConditionMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (condition := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_setConditionMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (condition := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_setConditionMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (condition := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_setConditionMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (condition := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_setConditionMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (condition := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_andRegister
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_andRegister
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_orRegister
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movToMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  change runNativeX87ReplayTemplateRoles pe imports (undefinedSlot + 19)
      (nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot frameAddress
        (nativeX87ReplayFixedTemplateCaptureSavedState table pe frameAddress
          input)) _ = _
  repeat' rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_nop
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movImmediateMemory
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (value := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_clearDirection
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_popReg
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_popReg
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_popReg
      (pe := pe) (imports := imports) (rva := _) (size := _)
      (undefinedSlot := _) (destination := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  simp only [runNativeX87ReplayTemplateRoles,
    NativeX87ReplayTemplateRole.semanticStep_popReg]
  rw [← nativeX87ReplayFixedTemplateCaptureReturnRva runtimeTarget]
  congr 1

private def nativeX87ReplayPrivateStackByte
    (caller : MachineState) (offset : Nat) : Word :=
  caller.registers.esp - BitVec.ofNat 32 20 + BitVec.ofNat 32 offset

private theorem nativeX87ReplayPrivateStackByte_add
    (caller : MachineState) (offset byte : Nat) :
    nativeX87ReplayPrivateStackByte caller offset + BitVec.ofNat 32 byte =
      nativeX87ReplayPrivateStackByte caller (offset + byte) := by
  simp [nativeX87ReplayPrivateStackByte, BitVec.add_assoc, ← BitVec.ofNat_add,
    Nat.add_assoc]

private theorem nativeX87ReplayPrivateStackWordFits
    (caller : MachineState) (offset : Nat)
    (stackValid :
      (caller.registers.esp - BitVec.ofNat 32 20).toNat + 20 <= 2 ^ 32)
    (inside : offset + 4 <= 20) :
    (nativeX87ReplayPrivateStackByte caller offset).toNat + 4 <= 2 ^ 32 := by
  have sumBefore :
      (caller.registers.esp - BitVec.ofNat 32 20).toNat + offset < 2 ^ 32 := by
    omega
  simp only [nativeX87ReplayPrivateStackByte, BitVec.toNat_add,
    BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega : offset < 2 ^ 32),
    Nat.mod_eq_of_lt sumBefore]
  omega

private theorem nativeX87ReplayPrivateStackWordsAvoid
    (caller : MachineState) (leftOffset rightOffset : Nat)
    (leftInside : leftOffset + 4 <= 20)
    (rightInside : rightOffset + 4 <= 20)
    (separated :
      leftOffset + 4 <= rightOffset ∨ rightOffset + 4 <= leftOffset) :
    Write32AvoidsWord
      (nativeX87ReplayPrivateStackByte caller leftOffset)
      (nativeX87ReplayPrivateStackByte caller rightOffset) := by
  intro leftByte leftBefore rightByte rightBefore overlap
  have leftExact :
      nativeX87ReplayPrivateStackByte caller leftOffset +
          BitVec.ofNat 32 leftByte =
        nativeX87ReplayPrivateStackByte caller (leftOffset + leftByte) :=
    nativeX87ReplayPrivateStackByte_add caller leftOffset leftByte
  have rightExact :
      nativeX87ReplayPrivateStackByte caller rightOffset +
          BitVec.ofNat 32 rightByte =
        nativeX87ReplayPrivateStackByte caller (rightOffset + rightByte) :=
    nativeX87ReplayPrivateStackByte_add caller rightOffset rightByte
  rw [leftExact, rightExact] at overlap
  have offsetsEqual :
      BitVec.ofNat 32 (leftOffset + leftByte) =
        BitVec.ofNat 32 (rightOffset + rightByte) := by
    have cancelled := congrArg
      (fun value =>
        value - (caller.registers.esp - BitVec.ofNat 32 20)) overlap
    simpa [nativeX87ReplayPrivateStackByte, BitVec.add_comm] using cancelled
  have naturals := congrArg BitVec.toNat offsetsEqual
  have leftBound : leftOffset + leftByte < 2 ^ 32 := by omega
  have rightBound : rightOffset + rightByte < 2 ^ 32 := by omega
  simp only [BitVec.toNat_ofNat, Nat.mod_eq_of_lt leftBound,
    Nat.mod_eq_of_lt rightBound] at naturals
  omega

private theorem nativeX87ReplayPrivateStackWriteAgreesOutside
    (caller : MachineState) (before : Memory) (offset : Nat) (value : Word)
    (inside : offset + 4 <= 20) :
    MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
      (before.write32 (nativeX87ReplayPrivateStackByte caller offset) value)
      before := by
  apply MemoryAgreesOutside.write32Inside
  intro byte byteBefore
  rw [nativeX87ReplayPrivateStackByte_add]
  exact ⟨offset + byte, by omega, rfl⟩

private theorem memoryAgreesOutside_readBytes_of_disjoint
    (frame : MemoryAgreesOutside footprint after before)
    (disjoint : CandidateFootprintsDisjoint footprint
      (nativeX87ReplayByteRange address count)) :
    Engine.readBytes after address count =
      Engine.readBytes before address count := by
  unfold Engine.readBytes
  apply List.map_congr_left
  intro offset offsetMember
  apply frame
  intro changed
  exact disjoint _ changed
    ⟨offset, List.mem_range.mp offsetMember, rfl⟩

private theorem memoryAgreesOutside_read32_of_disjoint
    (frame : MemoryAgreesOutside footprint after before)
    (disjoint : CandidateFootprintsDisjoint footprint
      (nativeX87ReplayByteRange address 4)) :
    Memory.read32 after address = Memory.read32 before address := by
  have byte0 : after address = before address := by
    apply frame
    exact disjoint.symm address ⟨0, by omega, by simp⟩
  have byte1 :
      after (address + BitVec.ofNat 32 1) =
        before (address + BitVec.ofNat 32 1) := by
    apply frame
    exact disjoint.symm _ ⟨1, by omega, rfl⟩
  have byte2 :
      after (address + BitVec.ofNat 32 2) =
        before (address + BitVec.ofNat 32 2) := by
    apply frame
    exact disjoint.symm _ ⟨2, by omega, rfl⟩
  have byte3 :
      after (address + BitVec.ofNat 32 3) =
        before (address + BitVec.ofNat 32 3) := by
    apply frame
    exact disjoint.symm _ ⟨3, by omega, rfl⟩
  unfold Memory.read32
  rw [byte0, byte1, byte2, byte3]

private theorem nativeX87ReplayByteRangesDisjoint
    (base : Word) (leftOffset leftBytes rightOffset rightBytes : Nat)
    (leftBound : leftOffset + leftBytes < 2 ^ 32)
    (rightBound : rightOffset + rightBytes < 2 ^ 32)
    (separated : leftOffset + leftBytes <= rightOffset ∨
      rightOffset + rightBytes <= leftOffset) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayByteRange
        (base + BitVec.ofNat 32 leftOffset) leftBytes)
      (nativeX87ReplayByteRange
        (base + BitVec.ofNat 32 rightOffset) rightBytes) := by
  intro address leftMember rightMember
  rcases leftMember with ⟨leftByte, leftByteBefore, rfl⟩
  rcases rightMember with ⟨rightByte, rightByteBefore, overlap⟩
  have overlap' :
      base + BitVec.ofNat 32 (leftOffset + leftByte) =
        base + BitVec.ofNat 32 (rightOffset + rightByte) := by
    simpa [BitVec.add_assoc, ← BitVec.ofNat_add, Nat.add_assoc] using overlap
  have constants := congrArg (fun value => value - base) overlap'
  simp only [BitVec.add_comm base, BitVec.add_sub_cancel] at constants
  have naturals := congrArg BitVec.toNat constants
  have leftBefore : leftOffset + leftByte < 2 ^ 32 := by omega
  have rightBefore : rightOffset + rightByte < 2 ^ 32 := by omega
  simp only [BitVec.toNat_ofNat, Nat.mod_eq_of_lt leftBefore,
    Nat.mod_eq_of_lt rightBefore] at naturals
  omega

private def nativeX87ReplayEntrySavedState
    (returnAddress : Nat) (caller : MachineState) : MachineState :=
  nativeX87ReplayPushRegState .edi
    (nativeX87ReplayPushRegState .esi
      (nativeX87ReplayPushRegState .ebx
        (nativeX87ReplayPushRegState .ebp
          (indirectCallEntryState returnAddress caller))))

private theorem word_sub_four_eq_sub_twenty_add_sixteen (value : Word) :
    value - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 20 + BitVec.ofNat 32 16 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem word_sub_four_twice_eq_sub_twenty_add_twelve (value : Word) :
    value - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 20 + BitVec.ofNat 32 12 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem word_sub_four_thrice_eq_sub_twenty_add_eight (value : Word) :
    value - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 20 + BitVec.ofNat 32 8 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem word_sub_four_four_times_eq_sub_twenty_add_four (value : Word) :
    value - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 -
          BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 20 + BitVec.ofNat 32 4 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem word_sub_four_five_times_eq_sub_twenty (value : Word) :
    value - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 -
          BitVec.ofNat 32 4 - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 20 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

@[simp] private theorem nativeX87ReplayEntrySavedState_esp
    (returnAddress : Nat) (caller : MachineState) :
    (nativeX87ReplayEntrySavedState returnAddress caller).registers.esp =
      caller.registers.esp - BitVec.ofNat 32 20 := by
  simpa [nativeX87ReplayEntrySavedState, indirectCallEntryState,
    Registers.set] using
    word_sub_four_five_times_eq_sub_twenty caller.registers.esp

private theorem nativeX87ReplayEntrySavedState_memoryFrame
    (returnAddress : Nat) (caller : MachineState) :
    MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
      (nativeX87ReplayEntrySavedState returnAddress caller).memory
      caller.memory := by
  let callState := indirectCallEntryState returnAddress caller
  let ebpState := nativeX87ReplayPushRegState .ebp callState
  let ebxState := nativeX87ReplayPushRegState .ebx ebpState
  let esiState := nativeX87ReplayPushRegState .esi ebxState
  let ediState := nativeX87ReplayPushRegState .edi esiState
  have callAddress :
      caller.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 16 := by
    simpa [nativeX87ReplayPrivateStackByte] using
      word_sub_four_eq_sub_twenty_add_sixteen caller.registers.esp
  have ebpAddress :
      callState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 12 := by
    simpa [callState, indirectCallEntryState,
      nativeX87ReplayPrivateStackByte] using
      word_sub_four_twice_eq_sub_twenty_add_twelve caller.registers.esp
  have ebxAddress :
      ebpState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 8 := by
    simpa only [ebpState, callState, nativeX87ReplayPushRegState_registers,
      indirectCallEntryState, Registers.set, Registers.get,
      nativeX87ReplayPrivateStackByte] using
      word_sub_four_thrice_eq_sub_twenty_add_eight caller.registers.esp
  have esiAddress :
      ebxState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 4 := by
    simpa only [ebxState, ebpState, callState,
      nativeX87ReplayPushRegState_registers, indirectCallEntryState,
      Registers.set, Registers.get, nativeX87ReplayPrivateStackByte] using
      word_sub_four_four_times_eq_sub_twenty_add_four caller.registers.esp
  have ediAddress :
      esiState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 0 := by
    simpa only [esiState, ebxState, ebpState, callState,
      nativeX87ReplayPushRegState_registers, indirectCallEntryState,
      Registers.set, Registers.get, nativeX87ReplayPrivateStackByte,
      BitVec.add_zero] using
      word_sub_four_five_times_eq_sub_twenty caller.registers.esp
  have callFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        callState.memory caller.memory := by
    simpa [callState, indirectCallEntryState, callAddress] using
      nativeX87ReplayPrivateStackWriteAgreesOutside caller caller.memory 16
        (BitVec.ofNat 32 returnAddress) (by omega)
  have ebpFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        ebpState.memory callState.memory := by
    simp only [ebpState, nativeX87ReplayPushRegState_memory, ebpAddress]
    exact nativeX87ReplayPrivateStackWriteAgreesOutside caller callState.memory
      12 (callState.registers.get .ebp) (by omega)
  have ebxFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        ebxState.memory ebpState.memory := by
    simp only [ebxState, nativeX87ReplayPushRegState_memory, ebxAddress]
    exact nativeX87ReplayPrivateStackWriteAgreesOutside caller ebpState.memory
      8 (ebpState.registers.get .ebx) (by omega)
  have esiFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        esiState.memory ebxState.memory := by
    simp only [esiState, nativeX87ReplayPushRegState_memory, esiAddress]
    exact nativeX87ReplayPrivateStackWriteAgreesOutside caller ebxState.memory
      4 (ebxState.registers.get .esi) (by omega)
  have ediFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        ediState.memory esiState.memory := by
    simp only [ediState, nativeX87ReplayPushRegState_memory, ediAddress]
    exact nativeX87ReplayPrivateStackWriteAgreesOutside caller esiState.memory
      0 (esiState.registers.get .edi) (by omega)
  exact callFrame.trans
    (ebpFrame.trans (ebxFrame.trans (esiFrame.trans ediFrame)))

private theorem nativeX87ReplayEntrySavedState_returnAddress
    (returnAddress : Nat) (caller : MachineState)
    (stackValid :
      (caller.registers.esp - BitVec.ofNat 32 20).toNat + 20 <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayEntrySavedState returnAddress caller).memory
        (nativeX87ReplayPrivateStackByte caller 16) =
      BitVec.ofNat 32 returnAddress := by
  let callState := indirectCallEntryState returnAddress caller
  let ebpState := nativeX87ReplayPushRegState .ebp callState
  let ebxState := nativeX87ReplayPushRegState .ebx ebpState
  let esiState := nativeX87ReplayPushRegState .esi ebxState
  let ediState := nativeX87ReplayPushRegState .edi esiState
  have callAddress :
      caller.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 16 := by
    simpa [nativeX87ReplayPrivateStackByte] using
      word_sub_four_eq_sub_twenty_add_sixteen caller.registers.esp
  have ebpAddress :
      callState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 12 := by
    simpa [callState, indirectCallEntryState,
      nativeX87ReplayPrivateStackByte] using
      word_sub_four_twice_eq_sub_twenty_add_twelve caller.registers.esp
  have ebxAddress :
      ebpState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 8 := by
    simpa only [ebpState, callState, nativeX87ReplayPushRegState_registers,
      indirectCallEntryState, Registers.set, Registers.get,
      nativeX87ReplayPrivateStackByte] using
      word_sub_four_thrice_eq_sub_twenty_add_eight caller.registers.esp
  have esiAddress :
      ebxState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 4 := by
    simpa only [esiState, ebxState, ebpState, callState,
      nativeX87ReplayPushRegState_registers, indirectCallEntryState,
      Registers.set, Registers.get, nativeX87ReplayPrivateStackByte] using
      word_sub_four_four_times_eq_sub_twenty_add_four caller.registers.esp
  have ediAddress :
      esiState.registers.esp - BitVec.ofNat 32 4 =
        nativeX87ReplayPrivateStackByte caller 0 := by
    simpa only [esiState, ebxState, ebpState, callState,
      nativeX87ReplayPushRegState_registers, indirectCallEntryState,
      Registers.set, Registers.get, nativeX87ReplayPrivateStackByte,
      BitVec.add_zero] using
      word_sub_four_five_times_eq_sub_twenty caller.registers.esp
  change Memory.read32 ediState.memory
      (nativeX87ReplayPrivateStackByte caller 16) =
    BitVec.ofNat 32 returnAddress
  rw [show ediState.memory = esiState.memory.write32
      (nativeX87ReplayPrivateStackByte caller 0)
      (esiState.registers.get .edi) by
    simpa [ediState, ediAddress] using
      nativeX87ReplayPushRegState_memory .edi esiState]
  rw [Memory.read32_write32_of_avoids _ _ _ _
    (nativeX87ReplayPrivateStackWordsAvoid caller 16 0
      (by omega) (by omega) (Or.inr (by omega)))]
  rw [show esiState.memory = ebxState.memory.write32
      (nativeX87ReplayPrivateStackByte caller 4)
      (ebxState.registers.get .esi) by
    simpa [esiState, esiAddress] using
      nativeX87ReplayPushRegState_memory .esi ebxState]
  rw [Memory.read32_write32_of_avoids _ _ _ _
    (nativeX87ReplayPrivateStackWordsAvoid caller 16 4
      (by omega) (by omega) (Or.inr (by omega)))]
  rw [show ebxState.memory = ebpState.memory.write32
      (nativeX87ReplayPrivateStackByte caller 8)
      (ebpState.registers.get .ebx) by
    simpa [ebxState, ebxAddress] using
      nativeX87ReplayPushRegState_memory .ebx ebpState]
  rw [Memory.read32_write32_of_avoids _ _ _ _
    (nativeX87ReplayPrivateStackWordsAvoid caller 16 8
      (by omega) (by omega) (Or.inr (by omega)))]
  rw [show ebpState.memory = callState.memory.write32
      (nativeX87ReplayPrivateStackByte caller 12)
      (callState.registers.get .ebp) by
    simpa [ebpState, ebpAddress] using
      nativeX87ReplayPushRegState_memory .ebp callState]
  rw [Memory.read32_write32_of_avoids _ _ _ _
    (nativeX87ReplayPrivateStackWordsAvoid caller 16 12
      (by omega) (by omega) (Or.inr (by omega)))]
  change Memory.read32
      (caller.memory.write32
        (caller.registers.esp - BitVec.ofNat 32 4)
        (BitVec.ofNat 32 returnAddress))
      (nativeX87ReplayPrivateStackByte caller 16) =
    BitVec.ofNat 32 returnAddress
  rw [← callAddress]
  exact Memory.read32_write32_same_of_fits _ _ _
    (by
      simpa [callAddress] using
        nativeX87ReplayPrivateStackWordFits caller 16 stackValid (by omega))

private theorem nativeX87ReplayActiveCellRvaBounded
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    table.activeFramePointerRva + 4 <= pe.sizeOfImage := by
  have rangeChecked :
      writableNonExecutableRvaRange pe table.activeFramePointerRva 4 = true := by
    by_cases exact :
        writableNonExecutableRvaRange pe table.activeFramePointerRva 4 = true
    · exact exact
    · have shape := runtimeTarget.target.static.shapeChecked
      simp [NativeX87ReplayBridgeTable.shapeChecked,
        NativeX87ReplayBridgeTable.layoutChecked, exact] at shape
  unfold writableNonExecutableRvaRange at rangeChecked
  simp only [Bool.and_eq_true, decide_eq_true_eq] at rangeChecked
  exact rangeChecked.1.2

private theorem nativeX87ReplayBridgeCellRvaBounded
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs) :
    runtimeTarget.target.descriptor.bridgeCell.cellRva + 4 <=
      pe.sizeOfImage := by
  have descriptorChecked :=
    runtimeTarget.target.static.descriptorChecked
      runtimeTarget.target.descriptor runtimeTarget.target.descriptorMember
  have pointerChecked :
      exactRelocatedImmutablePointer pe imports relocations
          (runtimeTarget.target.descriptor.descriptorRva +
            nativeX87ReplayBridgeFieldOffset)
          runtimeTarget.target.descriptor.bridge.entry.rva = true := by
    by_cases exact :
        exactRelocatedImmutablePointer pe imports relocations
            (runtimeTarget.target.descriptor.descriptorRva +
              nativeX87ReplayBridgeFieldOffset)
            runtimeTarget.target.descriptor.bridge.entry.rva = true
    · exact exact
    · simp [NativeX87ReplayBridgeDescriptor.checked, exact] at descriptorChecked
  by_cases bounded :
      runtimeTarget.target.descriptor.bridgeCell.cellRva + 4 <=
        pe.sizeOfImage
  · exact bounded
  · have tooLarge :
        runtimeTarget.target.descriptor.bridgeCell.cellRva + 4 >
          pe.sizeOfImage := by omega
    have tooLarge' :
        pe.sizeOfImage <
          runtimeTarget.target.descriptor.descriptorRva +
            nativeX87ReplayBridgeFieldOffset + 4 := by
      simpa [NativeX87ReplayBridgeDescriptor.bridgeCell] using tooLarge
    simp [exactRelocatedImmutablePointer, readImmutableRvaU32,
      immutableRvaBytes, tooLarge'] at pointerChecked

private theorem nativeX87ReplayPrivateStackDisjointActiveCell
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayPrivateStackFootprint caller)
      (nativeX87ReplayByteRange
        (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) 4) := by
  intro address stackMember activeMember
  apply source.privateStackDisjointImage address stackMember
  rcases activeMember with ⟨byte, byteBefore, rfl⟩
  have activeRvaBounded := nativeX87ReplayActiveCellRvaBounded runtimeTarget
  have absoluteBefore :
      pe.imageBase + table.activeFramePointerRva + byte < 2 ^ 32 := by
    omega
  have addressExact :
      (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva) +
          BitVec.ofNat 32 byte).toNat =
        pe.imageBase + table.activeFramePointerRva + byte := by
    simp [← BitVec.ofNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt absoluteBefore]
  rw [addressExact]
  constructor <;> omega

private theorem candidateFootprintDisjointFromImage_byteRange
    (candidatePe : PE32) (footprint : CandidateFootprint)
    (rva bytes : Nat)
    (footprintDisjoint :
      CandidateFootprintDisjointFromImage candidatePe footprint)
    (imageBounded :
      candidatePe.imageBase + candidatePe.sizeOfImage <= 2 ^ 32)
    (rangeBounded : rva + bytes <= candidatePe.sizeOfImage) :
    CandidateFootprintsDisjoint footprint
      (nativeX87ReplayByteRange
        (BitVec.ofNat 32 (candidatePe.imageBase + rva)) bytes) := by
  intro address footprintMember rangeMember
  apply footprintDisjoint address footprintMember
  rcases rangeMember with ⟨byte, byteBefore, rfl⟩
  have absoluteBefore :
      candidatePe.imageBase + rva + byte < 2 ^ 32 := by
    omega
  have addressExact :
      (BitVec.ofNat 32 (candidatePe.imageBase + rva) +
          BitVec.ofNat 32 byte).toNat =
        candidatePe.imageBase + rva + byte := by
    simp [← BitVec.ofNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt absoluteBefore]
  rw [addressExact]
  constructor <;> omega

private def nativeX87ReplayFixedTemplateEntryLoadedState
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (caller : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .eax
    (.memory (nativeX87ReplayAddressing none
      ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))))
    (nativeX87ReplayEntrySavedState
      (pe.imageBase + table.continuationRva) caller)

private def nativeX87ReplayFixedTemplateEntryStoredState
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (caller : MachineState) : MachineState :=
  nativeX87ReplayMovToMemoryState
    (nativeX87ReplayAddressing (some .eax) 12) .esp
    (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller)

private theorem nativeX87ReplayFixedTemplateEntryLoadedState_memory
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (caller : MachineState) :
    (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller).memory =
      (nativeX87ReplayEntrySavedState
        (pe.imageBase + table.continuationRva) caller).memory :=
  nativeX87ReplayMovFromOperandState_memory _ _ _

private theorem nativeX87ReplayFixedTemplateEntryStoredState_x87Semantics
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (caller : MachineState) :
    (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).x87Semantics =
      caller.x87Semantics := by
  unfold nativeX87ReplayFixedTemplateEntryStoredState
    nativeX87ReplayFixedTemplateEntryLoadedState
    nativeX87ReplayEntrySavedState
  rw [nativeX87ReplayMovToMemoryState_x87Semantics,
    nativeX87ReplayMovFromOperandState_x87Semantics]
  repeat rw [nativeX87ReplayPushRegState_x87Semantics]
  rfl

private theorem nativeX87ReplayFixedTemplateEntryLoadedEax
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller).registers.eax =
      source.frameAddress := by
  let activeAddress : Word :=
    BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)
  let activeOperand : Operand32 :=
    nativeX87ReplayMemory none
      ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))
  let saved := nativeX87ReplayEntrySavedState
    (pe.imageBase + table.continuationRva) caller
  have savedFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        saved.memory caller.memory :=
    nativeX87ReplayEntrySavedState_memoryFrame
      (pe.imageBase + table.continuationRva) caller
  have activeRead :
      Memory.read32 saved.memory activeAddress = source.frameAddress := by
    exact (memoryAgreesOutside_read32_of_disjoint savedFrame
      (nativeX87ReplayPrivateStackDisjointActiveCell runtimeTarget originalPe
        caller logicalInput source imageBounded)).trans source.activeBefore
  calc
    (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller).registers.eax =
        (readOperand32 initialSymbolic activeOperand).eval saved := by
      simpa [nativeX87ReplayFixedTemplateEntryLoadedState, activeOperand, saved,
        nativeX87ReplayMemory] using
        nativeX87ReplayMovFromOperandState_register .eax activeOperand saved
    _ = Memory.read32 saved.memory activeAddress := by
      rw [readNativeX87ReplayMemoryNone]
      change
        Memory.read32 saved.memory
            (BitVec.ofNat 32
              ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
          _
      rw [wordOfNat_mod_wordSize]
    _ = source.frameAddress := activeRead

private theorem nativeX87ReplayFixedTemplatePrivateStackDisjointInputFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayPrivateStackFootprint caller)
      (nativeX87ReplayByteRange
        (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
        kernelX87FrameBytes) := by
  intro address privateMember inputMember
  apply source.privateStackDisjointFrame address privateMember
  rcases inputMember with ⟨offset, offsetBefore, rfl⟩
  refine ⟨nativeX87FrameInputX87Offset + offset, ?_, ?_⟩
  · simp [kernelX87FrameBytes] at offsetBefore
    simp [nativeX87ReplayFrameBytes, nativeX87FrameInputX87Offset,
      nativeX87FrameOutputX87Offset, kernelX87FrameBytes]
    omega
  · simp [BitVec.add_assoc, ← BitVec.ofNat_add]

private theorem nativeX87ReplayFixedTemplateEntryStoredEncoded
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    Engine.readBytes
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory
        (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
        kernelX87FrameBytes =
      encodeKernelX87Frame source.inputCandidate := by
  let saved := nativeX87ReplayEntrySavedState
    (pe.imageBase + table.continuationRva) caller
  let loaded := nativeX87ReplayFixedTemplateEntryLoadedState table pe caller
  let stored := nativeX87ReplayFixedTemplateEntryStoredState table pe caller
  have loadedEax : loaded.registers.eax = source.frameAddress := by
    exact nativeX87ReplayFixedTemplateEntryLoadedEax runtimeTarget originalPe
      caller logicalInput source imageBounded
  have savedFrame :
      MemoryAgreesOutside (nativeX87ReplayPrivateStackFootprint caller)
        saved.memory caller.memory :=
    nativeX87ReplayEntrySavedState_memoryFrame
      (pe.imageBase + table.continuationRva) caller
  have savedEncoded :
      Engine.readBytes saved.memory
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
          kernelX87FrameBytes =
        encodeKernelX87Frame source.inputCandidate := by
    rw [memoryAgreesOutside_readBytes_of_disjoint savedFrame
      (nativeX87ReplayFixedTemplatePrivateStackDisjointInputFrame runtimeTarget
        originalPe caller logicalInput source)]
    exact source.inputFrame.encoded
  have loadedEncoded :
      Engine.readBytes loaded.memory
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
          kernelX87FrameBytes =
        encodeKernelX87Frame source.inputCandidate := by
    simpa [loaded, nativeX87ReplayFixedTemplateEntryLoadedState, saved,
      nativeX87ReplayMemory] using savedEncoded
  have privateAddress :
      ((nativeX87ReplayAddressing (some .eax) 12).expression
          initialSymbolic.registers).eval loaded =
        source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset := by
    have loadedEaxGet : loaded.registers.get .eax = source.frameAddress := by
      simpa [Registers.get] using loadedEax
    simp [loadedEaxGet, nativeX87FramePrivateEspOffset]
  have storedMemory :
      stored.memory =
        loaded.memory.write32
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset)
          loaded.registers.esp := by
    rw [show stored.memory =
        loaded.memory.write32
          (((nativeX87ReplayAddressing (some .eax) 12).expression
            initialSymbolic.registers).eval loaded)
          (loaded.registers.get .esp) by
      simpa [stored, nativeX87ReplayFixedTemplateEntryStoredState, loaded,
        nativeX87FramePrivateEspOffset] using
        nativeX87ReplayMovToMemoryState_memory
          (nativeX87ReplayAddressing (some .eax) 12) .esp loaded]
    rw [privateAddress]
    rfl
  have storedFrame :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4)
        stored.memory loaded.memory := by
    rw [storedMemory]
    apply MemoryAgreesOutside.write32Inside
    intro byte byteBefore
    exact ⟨byte, byteBefore, rfl⟩
  have storeDisjointInputFrame :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4)
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameInputX87Offset)
          kernelX87FrameBytes) := by
    simpa using nativeX87ReplayByteRangesDisjoint source.frameAddress
      nativeX87FramePrivateEspOffset 4 nativeX87FrameInputX87Offset
      kernelX87FrameBytes (by decide) (by decide) (Or.inl (by decide))
  change Engine.readBytes stored.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
      kernelX87FrameBytes =
    encodeKernelX87Frame source.inputCandidate
  rw [memoryAgreesOutside_readBytes_of_disjoint storedFrame
    storeDisjointInputFrame]
  exact loadedEncoded

private def nativeX87ReplayFixedTemplateEntryPreparationFootprint
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) : CandidateFootprint :=
  fun address =>
    nativeX87ReplayPrivateStackFootprint caller address ∨
      nativeX87ReplayByteRange
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4 address

private theorem
    nativeX87ReplayFixedTemplateEntryPreparationDisjointRepresentation
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    FootprintDisjointFromRepresentation source.rep
      (nativeX87ReplayFixedTemplateEntryPreparationFootprint source) := by
  intro address member observed
  rcases member with privateMember | frameMember
  · exact source.privateStackDisjointRepresentation address privateMember observed
  · apply source.stackDisjoint address
    · rcases frameMember with ⟨byte, byteBefore, rfl⟩
      exact ⟨nativeX87FramePrivateEspOffset + byte, by
        simp [nativeX87ReplayFrameBytes, nativeX87FramePrivateEspOffset,
          nativeX87FrameOutputX87Offset, kernelX87FrameBytes]
        omega, by
        simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
    · exact observed

private theorem nativeX87ReplayFixedTemplateEntryStoredMemoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    MemoryAgreesOutside
      (nativeX87ReplayFixedTemplateEntryPreparationFootprint source)
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory
      caller.memory := by
  let saved := nativeX87ReplayEntrySavedState
    (pe.imageBase + table.continuationRva) caller
  let loaded := nativeX87ReplayFixedTemplateEntryLoadedState table pe caller
  let stored := nativeX87ReplayFixedTemplateEntryStoredState table pe caller
  have loadedEax : loaded.registers.eax = source.frameAddress :=
    nativeX87ReplayFixedTemplateEntryLoadedEax runtimeTarget originalPe caller
      logicalInput source imageBounded
  have loadedEaxGet :
      loaded.registers.get .eax = source.frameAddress := by
    simpa [Registers.get] using loadedEax
  have storedMemory :
      stored.memory =
        loaded.memory.write32
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset)
          loaded.registers.esp := by
    change stored.memory =
      loaded.memory.write32
        (source.frameAddress + BitVec.ofNat 32 12) loaded.registers.esp
    rw [show stored.memory =
        loaded.memory.write32
          (((nativeX87ReplayAddressing (some .eax) 12).expression
            initialSymbolic.registers).eval loaded)
          (loaded.registers.get .esp) by
      simpa [stored, nativeX87ReplayFixedTemplateEntryStoredState, loaded] using
        nativeX87ReplayMovToMemoryState_memory
          (nativeX87ReplayAddressing (some .eax) 12) .esp loaded]
    rw [nativeX87ReplayAddressing_some_eval, loadedEaxGet]
    rfl
  have loadedToCaller :
      MemoryAgreesOutside
        (nativeX87ReplayFixedTemplateEntryPreparationFootprint source)
        loaded.memory caller.memory := by
    intro address outside
    rw [show loaded.memory = saved.memory by
      exact nativeX87ReplayFixedTemplateEntryLoadedState_memory table pe caller]
    exact (nativeX87ReplayEntrySavedState_memoryFrame
      (pe.imageBase + table.continuationRva) caller) address
        (fun privateMember => outside (Or.inl privateMember))
  have storedToLoaded :
      MemoryAgreesOutside
        (nativeX87ReplayFixedTemplateEntryPreparationFootprint source)
        stored.memory loaded.memory := by
    rw [storedMemory]
    apply MemoryAgreesOutside.write32Inside
    intro byte byteBefore
    apply Or.inr
    exact ⟨byte, byteBefore, rfl⟩
  exact loadedToCaller.trans storedToLoaded

private theorem nativeX87ReplayEntryPreparationDisjointRequiredField
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (field : Engine.EngineField) (offset : Nat)
    (required : field ∈ source.rep.layout.requiredFields)
    (canonical : nativeX87ReplayEngineFieldOffset? field = some offset) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFixedTemplateEntryPreparationFootprint source)
      (nativeX87ReplayByteRange
        (source.outputAddress + BitVec.ofNat 32 offset) field.byteWidth) := by
  rcases source.engineRelated.repValid.1 with
    ⟨_stateSizePositive, _stateSizeBound, _fieldsNodup, _fieldsValid,
      _fieldsDisjoint, fieldsComplete⟩
  rcases List.mem_map.mp (fieldsComplete field required) with
    ⟨entry, entryMember, entryField⟩
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  have entryOffset := List.all_eq_true.mp layout.1.2 entry entryMember
  simp only [entryField, canonical, beq_iff_eq, Option.some.injEq] at entryOffset
  intro address preparationMember fieldMember
  apply
    nativeX87ReplayFixedTemplateEntryPreparationDisjointRepresentation source
      address preparationMember
  apply Or.inl
  rcases fieldMember with ⟨byte, byteBefore, rfl⟩
  refine ⟨entry, entryMember, byte, ?_, ?_⟩
  · simpa [entryField] using byteBefore
  · simp [Engine.EngineFieldLayout.address, entryOffset, source.engineBase,
      BitVec.add_assoc]

private theorem nativeX87ReplayFixedTemplateEntryRestoredReadRegisterAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (register : Reg) (offset : Nat)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.register register) = some offset) :
    Memory.read32
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)).memory
        (source.outputAddress + BitVec.ofNat 32 offset) =
      logicalInput.registers.get register := by
  have required :
      Engine.EngineField.register register ∈
        source.rep.layout.requiredFields := by
    cases register <;>
      simp [Engine.EngineLayout.requiredFields, Engine.allRegisters]
  have frame :=
    nativeX87ReplayFixedTemplateEntryStoredMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  have disjoint :=
    nativeX87ReplayEntryPreparationDisjointRequiredField source
      (Engine.EngineField.register register) offset required canonical
  calc
    _ = Memory.read32 caller.memory
        (source.outputAddress + BitVec.ofNat 32 offset) := by
      simpa [nativeX87ReplayFrStorState] using
        memoryAgreesOutside_read32_of_disjoint frame disjoint
    _ = logicalInput.registers.get register :=
      source.readRegisterAtOffset register offset canonical

private theorem
    nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (register : Reg) (offset : Nat)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.register register) = some offset) :
    Memory.read32
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)).memory
        (source.inputAddress + BitVec.ofNat 32 offset) =
      logicalInput.registers.get register := by
  rw [source.inputOutputAlias]
  exact nativeX87ReplayFixedTemplateEntryRestoredReadRegisterAtOffset
    runtimeTarget originalPe caller logicalInput source imageBounded register
    offset canonical

private theorem nativeX87ReplayFixedTemplateEntryRestoredReadInputEflags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)).memory
        (source.inputAddress + BitVec.ofNat 32 240) =
      logicalInput.eflags := by
  have required :
      Engine.EngineField.eflags ∈ source.rep.layout.requiredFields := by
    simp [Engine.EngineLayout.requiredFields]
  have frame :=
    nativeX87ReplayFixedTemplateEntryStoredMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  have disjoint :=
    nativeX87ReplayEntryPreparationDisjointRequiredField source
      Engine.EngineField.eflags 240 required (by decide)
  calc
    _ = Memory.read32 caller.memory
        (source.inputAddress + BitVec.ofNat 32 240) := by
      simpa [nativeX87ReplayFrStorState] using
        memoryAgreesOutside_read32_of_disjoint frame
          (by simpa [source.inputOutputAlias] using disjoint)
    _ = logicalInput.eflags := source.readInputEflags

private theorem nativeX87ReplayEntryPreparationDisjointInputPointer
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFixedTemplateEntryPreparationFootprint source)
      (nativeX87ReplayByteRange
        (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) 4) := by
  intro address preparationMember inputMember
  rcases preparationMember with privateMember | frameSlotMember
  · apply source.privateStackDisjointFrame address privateMember
    rcases inputMember with ⟨byte, byteBefore, rfl⟩
    exact ⟨nativeX87FrameInputOffset + byte, by
      simp [nativeX87ReplayFrameBytes, nativeX87FrameInputOffset,
        nativeX87FrameOutputX87Offset, kernelX87FrameBytes]
      omega, by
      simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
  · exact
      (nativeX87ReplayByteRangesDisjoint source.frameAddress
        nativeX87FramePrivateEspOffset 4 nativeX87FrameInputOffset 4
        (by decide) (by decide) (Or.inr (by decide)))
        address frameSlotMember inputMember

private theorem
    nativeX87ReplayFixedTemplateEntryRestoredInputPointer
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)).memory
        (source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) =
      source.inputAddress := by
  have frame :=
    nativeX87ReplayFixedTemplateEntryStoredMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  calc
    _ = Memory.read32 caller.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FrameInputOffset) := by
      simpa [nativeX87ReplayFrStorState] using
        memoryAgreesOutside_read32_of_disjoint frame
          (nativeX87ReplayEntryPreparationDisjointInputPointer source)
    _ = source.inputAddress := source.inputPointer

private theorem nativeX87ReplayFixedTemplateEntryRestoredEax
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    (nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)).registers.eax =
        source.frameAddress := by
  calc
    _ = (nativeX87ReplayFixedTemplateEntryStoredState table pe
          caller).registers.eax := rfl
    _ = (nativeX87ReplayFixedTemplateEntryLoadedState table pe
          caller).registers.eax := by
      simpa [nativeX87ReplayFixedTemplateEntryStoredState] using
        congrArg Registers.eax
          (nativeX87ReplayMovToMemoryState_registers
            (nativeX87ReplayAddressing (some .eax) 12) .esp
            (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller))
    _ = source.frameAddress :=
      nativeX87ReplayFixedTemplateEntryLoadedEax runtimeTarget originalPe caller
        logicalInput source imageBounded

private theorem nativeX87ReplayFixedTemplateEntryFrStorAddress
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    kernelX87FrameAddress (nativeX87ReplayAddressing (some .eax)
        nativeX87FrameInputX87Offset)
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller) =
      source.frameAddress +
        BitVec.ofNat 32 nativeX87FrameInputX87Offset := by
  have loadedEax :=
    nativeX87ReplayFixedTemplateEntryLoadedEax runtimeTarget originalPe caller
      logicalInput source imageBounded
  have registersExact :
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).registers =
        (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller).registers :=
    nativeX87ReplayMovToMemoryState_registers
      (nativeX87ReplayAddressing (some .eax) 12) .esp
      (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller)
  have loadedEaxGet :
      (nativeX87ReplayFixedTemplateEntryLoadedState table pe caller).registers.get
          .eax =
        source.frameAddress := by
    simpa [Registers.get] using loadedEax
  unfold kernelX87FrameAddress
  rw [nativeX87ReplayAddressing_some_eval, registersExact, loadedEaxGet]

/-- The frame and memory admission proof for the single `FRSTOR` transition is
kept independent of role-list composition. -/
private theorem nativeX87ReplayFixedTemplateEntryFrStor_exact
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    (NativeX87ReplayTemplateRole.x87Frame
      (runtimeTarget.target.frameMapping.bridgeTargetRva + 12) {
        operation := .frStor
        addressing := nativeX87ReplayAddressing (some .eax) 20
        size := 3
      }).semanticStep pe imports 6
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller) =
      .running
        (runtimeTarget.target.frameMapping.bridgeTargetRva + 15) 7
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)) := by
  apply NativeX87ReplayTemplateRole.semanticStep_frStor
    (address :=
      source.frameAddress + BitVec.ofNat 32 nativeX87FrameInputX87Offset)
  · exact nativeX87ReplayFixedTemplateEntryFrStorAddress runtimeTarget originalPe
      caller logicalInput source imageBounded
  · exact source.inputX87FrameAddressValid
  · exact nativeX87ReplayFixedTemplateEntryStoredEncoded runtimeTarget originalPe
      caller logicalInput source imageBounded
  · exact source.inputCandidateRepresentable

/-- Execute the seven-role entry prefix using the opaque checked `FRSTOR`
transition.  The resulting term contains only the linear role composition. -/
private theorem nativeX87ReplayFixedTemplateEntryRoles_afterRestore
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    runNativeX87ReplayTemplateRoles pe imports 0
        (indirectCallEntryState
          (pe.imageBase + table.continuationRva) caller)
        (nativeX87ReplayFixedTemplateEntryRoles table pe
          runtimeTarget.target.frameMapping) =
      runNativeX87ReplayTemplateRoles pe imports 7
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))
        ((nativeX87ReplayFixedTemplateEntryRoles table pe
          runtimeTarget.target.frameMapping).drop 7) := by
  let stored :=
    nativeX87ReplayFixedTemplateEntryStoredState table pe caller
  have frStorExact :=
    nativeX87ReplayFixedTemplateEntryFrStor_exact runtimeTarget originalPe caller
      logicalInput source imageBounded
  simp only [nativeX87ReplayFixedTemplateEntryRoles,
    nativeX87ReplayOrdinaryRole, nativeX87ReplayMemory]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushReg
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushReg
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushReg
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushReg
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movToMemory
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [show 0 + 1 + 1 + 1 + 1 + 1 + 1 = 6 by decide]
  change runNativeX87ReplayTemplateRoles pe imports 6
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller) _ = _
  rw [runNativeX87ReplayTemplateRoles_cons_running frStorExact
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rfl

private def nativeX87ReplayFixedTemplateEntryInputLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .eax
    (nativeX87ReplayMemory (some .eax) nativeX87FrameInputOffset) input

private def nativeX87ReplayFixedTemplateEntryEbxLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ebx
    (nativeX87ReplayMemory (some .eax) 4)
    (nativeX87ReplayFixedTemplateEntryInputLoadedState input)

private def nativeX87ReplayFixedTemplateEntryEcxLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ecx
    (nativeX87ReplayMemory (some .eax) 8)
    (nativeX87ReplayFixedTemplateEntryEbxLoadedState input)

private def nativeX87ReplayFixedTemplateEntryEsiLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .esi
    (nativeX87ReplayMemory (some .eax) 16)
    (nativeX87ReplayFixedTemplateEntryEcxLoadedState input)

private def nativeX87ReplayFixedTemplateEntryEdiLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .edi
    (nativeX87ReplayMemory (some .eax) 20)
    (nativeX87ReplayFixedTemplateEntryEsiLoadedState input)

private def nativeX87ReplayFixedTemplateEntryEbpLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .ebp
    (nativeX87ReplayMemory (some .eax) 24)
    (nativeX87ReplayFixedTemplateEntryEdiLoadedState input)

private def nativeX87ReplayFixedTemplateEntryLogicalRegistersState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .esp
    (nativeX87ReplayMemory (some .eax) 28)
    (nativeX87ReplayFixedTemplateEntryEbpLoadedState input)

private def nativeX87ReplayFixedTemplateEntryFlagsSavedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayPushOperandState
    (nativeX87ReplayMemory (some .eax) 240)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input)

private def nativeX87ReplayFixedTemplateEntryEaxSavedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayPushOperandState
    (nativeX87ReplayMemory (some .eax) 0)
    (nativeX87ReplayFixedTemplateEntryFlagsSavedState input)

private def nativeX87ReplayFixedTemplateEntryEdxLoadedState
    (input : MachineState) : MachineState :=
  nativeX87ReplayMovFromOperandState .edx
    (nativeX87ReplayMemory (some .eax) 12)
    (nativeX87ReplayFixedTemplateEntryEaxSavedState input)

private def nativeX87ReplayFixedTemplateEntryEaxRestoredState
    (input : MachineState) : MachineState :=
  nativeX87ReplayPopRegState .eax
    (nativeX87ReplayFixedTemplateEntryEdxLoadedState input)

private def nativeX87ReplayFixedTemplateEntryFlagsRestoredState
    (input : MachineState) : MachineState :=
  nativeX87ReplayPopFlagsState
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState input)

private def nativeX87ReplayFixedTemplateEntrySuffixState
    (input : MachineState) : MachineState :=
  nativeX87ReplayNopState 3
    (nativeX87ReplayFixedTemplateEntryFlagsRestoredState input)

private def nativeX87ReplayFixedTemplateInstructionEntryState
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (inputCandidate : StageA.X87.PhysicalState)
    (caller : MachineState) : MachineState :=
  nativeX87ReplayFixedTemplateEntrySuffixState
    (nativeX87ReplayFrStorState inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))

private theorem nativeX87ReplayFixedTemplateEntryFlagsSavedState_eq
    (input : MachineState) :
    nativeX87ReplayFixedTemplateEntryFlagsSavedState input =
      nativeX87ReplayPushOperandState
        (nativeX87ReplayMemory (some .eax) 240)
        (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input) :=
  rfl

private theorem nativeX87ReplayFixedTemplateEntryEaxSavedState_eq
    (input : MachineState) :
    nativeX87ReplayFixedTemplateEntryEaxSavedState input =
      nativeX87ReplayPushOperandState
        (nativeX87ReplayMemory (some .eax) 0)
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState input) :=
  rfl

private theorem nativeX87ReplayFixedTemplateEntryEdxLoadedState_eq
    (input : MachineState) :
    nativeX87ReplayFixedTemplateEntryEdxLoadedState input =
      nativeX87ReplayMovFromOperandState .edx
        (nativeX87ReplayMemory (some .eax) 12)
        (nativeX87ReplayFixedTemplateEntryEaxSavedState input) :=
  rfl

private theorem nativeX87ReplayFixedTemplateEntryEaxRestoredState_eq
    (input : MachineState) :
    nativeX87ReplayFixedTemplateEntryEaxRestoredState input =
      nativeX87ReplayPopRegState .eax
        (nativeX87ReplayFixedTemplateEntryEdxLoadedState input) :=
  rfl

private theorem nativeX87ReplayFixedTemplateEntrySuffixState_eq
    (input : MachineState) :
    nativeX87ReplayFixedTemplateEntrySuffixState input =
      nativeX87ReplayNopState 3
        (nativeX87ReplayPopFlagsState
          (nativeX87ReplayFixedTemplateEntryEaxRestoredState input)) :=
  rfl

private theorem nativeX87ReplayFixedTemplateInstructionEntryState_eq
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (inputCandidate : StageA.X87.PhysicalState) (caller : MachineState) :
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
        inputCandidate caller =
      nativeX87ReplayFixedTemplateEntrySuffixState
        (nativeX87ReplayFrStorState inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)) :=
  rfl

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryInputLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryInputLoadedState input).memory =
      input.memory := by
  exact nativeX87ReplayMovFromOperandState_memory _ _ _

private theorem nativeX87ReplayFixedTemplateEntryInputLoadedState_eax
    (input : MachineState) (frameAddress inputAddress : Word)
    (eaxExact : input.registers.eax = frameAddress)
    (inputRead :
      Memory.read32 input.memory
          (frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) =
        inputAddress) :
    (nativeX87ReplayFixedTemplateEntryInputLoadedState
      input).registers.eax = inputAddress := by
  calc
    _ = (readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax)
            nativeX87FrameInputOffset)).eval input :=
      nativeX87ReplayMovFromOperandState_register .eax _ input
    _ = Memory.read32 input.memory
          (input.registers.get .eax +
            BitVec.ofNat 32 nativeX87FrameInputOffset) :=
      readNativeX87ReplayMemorySome .eax nativeX87FrameInputOffset input
    _ = Memory.read32 input.memory
          (frameAddress + BitVec.ofNat 32 nativeX87FrameInputOffset) := by
      exact congrArg (Memory.read32 input.memory)
        (congrArg (fun address =>
          address + BitVec.ofNat 32 nativeX87FrameInputOffset)
          (by simpa [Registers.get] using eaxExact))
    _ = inputAddress := inputRead

private theorem
    nativeX87ReplayFixedTemplateEntryInputLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryInputLoadedState restored).registers =
      restored.registers.set .eax source.inputAddress := by
  dsimp only
  exact nativeX87ReplayMovFromEaxMemoryState_registers .eax
    nativeX87FrameInputOffset _ source.frameAddress source.inputAddress
    (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
      caller logicalInput source imageBounded)
    (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
      originalPe caller logicalInput source imageBounded)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEbxLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEbxLoadedState input).memory =
      input.memory := by
  rw [nativeX87ReplayFixedTemplateEntryEbxLoadedState,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayFixedTemplateEntryInputLoadedState_memory]

private theorem nativeX87ReplayFixedTemplateEntryEbxLoadedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryInputLoadedState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryEbxLoadedState
      input).registers.eax = inputAddress := by
  change
    (nativeX87ReplayMovFromOperandState .ebx
      (nativeX87ReplayMemory (some .eax) 4)
      (nativeX87ReplayFixedTemplateEntryInputLoadedState
        input)).registers.get .eax = inputAddress
  exact (nativeX87ReplayMovFromOperandState_register_other
    .ebx .eax _ _ (by decide)).trans
      (by simpa [Registers.get] using eaxExact)

private theorem nativeX87ReplayFixedTemplateEntryEbxLoadedState_ebx
    (input : MachineState) (inputAddress value : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryInputLoadedState
        input).registers.eax = inputAddress)
    (valueRead :
      Memory.read32 input.memory
          (inputAddress + BitVec.ofNat 32 4) = value) :
    (nativeX87ReplayFixedTemplateEntryEbxLoadedState
      input).registers.ebx = value := by
  calc
    _ = (readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) 4)).eval
            (nativeX87ReplayFixedTemplateEntryInputLoadedState input) :=
      nativeX87ReplayMovFromOperandState_register .ebx _ _
    _ = Memory.read32 input.memory
          (inputAddress + BitVec.ofNat 32 4) := by
      rw [readNativeX87ReplayMemorySome,
        nativeX87ReplayFixedTemplateEntryInputLoadedState_memory]
      exact congrArg (Memory.read32 input.memory)
        (congrArg (fun address => address + BitVec.ofNat 32 4)
          (by simpa [Registers.get] using eaxExact))
    _ = value := valueRead

private theorem nativeX87ReplayFixedTemplateEntryEbxLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEbxLoadedState restored).registers =
      (nativeX87ReplayFixedTemplateEntryInputLoadedState restored).registers.set
        .ebx logicalInput.registers.ebx := by
  dsimp only
  apply nativeX87ReplayMovFromEaxMemoryState_registers .ebx 4 _
    source.inputAddress logicalInput.registers.ebx
  · exact nativeX87ReplayFixedTemplateEntryInputLoadedState_eax _
      source.frameAddress source.inputAddress
      (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
        caller logicalInput source imageBounded)
      (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
        originalPe caller logicalInput source imageBounded)
  · simpa using
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .ebx 4 (by decide)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEcxLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEcxLoadedState input).memory =
      input.memory := by
  rw [nativeX87ReplayFixedTemplateEntryEcxLoadedState,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayFixedTemplateEntryEbxLoadedState_memory]

private theorem nativeX87ReplayFixedTemplateEntryEcxLoadedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryEbxLoadedState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryEcxLoadedState
      input).registers.eax = inputAddress := by
  change
    (nativeX87ReplayMovFromOperandState .ecx
      (nativeX87ReplayMemory (some .eax) 8)
      (nativeX87ReplayFixedTemplateEntryEbxLoadedState
        input)).registers.get .eax = inputAddress
  exact (nativeX87ReplayMovFromOperandState_register_other
    .ecx .eax _ _ (by decide)).trans
      (by simpa [Registers.get] using eaxExact)

private theorem nativeX87ReplayFixedTemplateEntryEcxLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEcxLoadedState restored).registers =
      (nativeX87ReplayFixedTemplateEntryEbxLoadedState restored).registers.set
        .ecx logicalInput.registers.ecx := by
  dsimp only
  apply nativeX87ReplayMovFromEaxMemoryState_registers .ecx 8 _
    source.inputAddress logicalInput.registers.ecx
  · apply nativeX87ReplayFixedTemplateEntryEbxLoadedState_eax _
      source.inputAddress
    exact nativeX87ReplayFixedTemplateEntryInputLoadedState_eax _
      source.frameAddress source.inputAddress
      (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
        caller logicalInput source imageBounded)
      (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
        originalPe caller logicalInput source imageBounded)
  · simpa using
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .ecx 8 (by decide)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEsiLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEsiLoadedState input).memory =
      input.memory := by
  rw [nativeX87ReplayFixedTemplateEntryEsiLoadedState,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayFixedTemplateEntryEcxLoadedState_memory]

private theorem nativeX87ReplayFixedTemplateEntryEsiLoadedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryEcxLoadedState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryEsiLoadedState
      input).registers.eax = inputAddress := by
  change
    (nativeX87ReplayMovFromOperandState .esi
      (nativeX87ReplayMemory (some .eax) 16)
      (nativeX87ReplayFixedTemplateEntryEcxLoadedState
        input)).registers.get .eax = inputAddress
  exact (nativeX87ReplayMovFromOperandState_register_other
    .esi .eax _ _ (by decide)).trans
      (by simpa [Registers.get] using eaxExact)

private theorem nativeX87ReplayFixedTemplateEntryEsiLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEsiLoadedState restored).registers =
      (nativeX87ReplayFixedTemplateEntryEcxLoadedState restored).registers.set
        .esi logicalInput.registers.esi := by
  dsimp only
  apply nativeX87ReplayMovFromEaxMemoryState_registers .esi 16 _
    source.inputAddress logicalInput.registers.esi
  · apply nativeX87ReplayFixedTemplateEntryEcxLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEbxLoadedState_eax
    exact nativeX87ReplayFixedTemplateEntryInputLoadedState_eax _
      source.frameAddress source.inputAddress
      (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
        caller logicalInput source imageBounded)
      (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
        originalPe caller logicalInput source imageBounded)
  · simpa using
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .esi 16 (by decide)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEdiLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEdiLoadedState input).memory =
      input.memory := by
  rw [nativeX87ReplayFixedTemplateEntryEdiLoadedState,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayFixedTemplateEntryEsiLoadedState_memory]

private theorem nativeX87ReplayFixedTemplateEntryEdiLoadedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryEsiLoadedState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryEdiLoadedState
      input).registers.eax = inputAddress := by
  change
    (nativeX87ReplayMovFromOperandState .edi
      (nativeX87ReplayMemory (some .eax) 20)
      (nativeX87ReplayFixedTemplateEntryEsiLoadedState
        input)).registers.get .eax = inputAddress
  exact (nativeX87ReplayMovFromOperandState_register_other
    .edi .eax _ _ (by decide)).trans
      (by simpa [Registers.get] using eaxExact)

private theorem nativeX87ReplayFixedTemplateEntryEdiLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEdiLoadedState restored).registers =
      (nativeX87ReplayFixedTemplateEntryEsiLoadedState restored).registers.set
        .edi logicalInput.registers.edi := by
  dsimp only
  apply nativeX87ReplayMovFromEaxMemoryState_registers .edi 20 _
    source.inputAddress logicalInput.registers.edi
  · apply nativeX87ReplayFixedTemplateEntryEsiLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEcxLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEbxLoadedState_eax
    exact nativeX87ReplayFixedTemplateEntryInputLoadedState_eax _
      source.frameAddress source.inputAddress
      (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
        caller logicalInput source imageBounded)
      (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
        originalPe caller logicalInput source imageBounded)
  · simpa using
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .edi 20 (by decide)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEbpLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEbpLoadedState input).memory =
      input.memory := by
  rw [nativeX87ReplayFixedTemplateEntryEbpLoadedState,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayFixedTemplateEntryEdiLoadedState_memory]

private theorem nativeX87ReplayFixedTemplateEntryEbpLoadedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryEdiLoadedState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryEbpLoadedState
      input).registers.eax = inputAddress := by
  change
    (nativeX87ReplayMovFromOperandState .ebp
      (nativeX87ReplayMemory (some .eax) 24)
      (nativeX87ReplayFixedTemplateEntryEdiLoadedState
        input)).registers.get .eax = inputAddress
  exact (nativeX87ReplayMovFromOperandState_register_other
    .ebp .eax _ _ (by decide)).trans
      (by simpa [Registers.get] using eaxExact)

private theorem nativeX87ReplayFixedTemplateEntryEbpLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEbpLoadedState restored).registers =
      (nativeX87ReplayFixedTemplateEntryEdiLoadedState restored).registers.set
        .ebp logicalInput.registers.ebp := by
  dsimp only
  apply nativeX87ReplayMovFromEaxMemoryState_registers .ebp 24 _
    source.inputAddress logicalInput.registers.ebp
  · apply nativeX87ReplayFixedTemplateEntryEdiLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEsiLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEcxLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEbxLoadedState_eax
    exact nativeX87ReplayFixedTemplateEntryInputLoadedState_eax _
      source.frameAddress source.inputAddress
      (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
        caller logicalInput source imageBounded)
      (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
        originalPe caller logicalInput source imageBounded)
  · simpa using
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .ebp 24 (by decide)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input).memory =
      input.memory := by
  rw [nativeX87ReplayFixedTemplateEntryLogicalRegistersState,
    nativeX87ReplayMovFromOperandState_memory,
    nativeX87ReplayFixedTemplateEntryEbpLoadedState_memory]

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).registers =
      (nativeX87ReplayFixedTemplateEntryEbpLoadedState restored).registers.set
        .esp logicalInput.registers.esp := by
  dsimp only
  apply nativeX87ReplayMovFromEaxMemoryState_registers .esp 28 _
    source.inputAddress logicalInput.registers.esp
  · apply nativeX87ReplayFixedTemplateEntryEbpLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEdiLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEsiLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEcxLoadedState_eax
    apply nativeX87ReplayFixedTemplateEntryEbxLoadedState_eax
    exact nativeX87ReplayFixedTemplateEntryInputLoadedState_eax _
      source.frameAddress source.inputAddress
      (nativeX87ReplayFixedTemplateEntryRestoredEax runtimeTarget originalPe
        caller logicalInput source imageBounded)
      (nativeX87ReplayFixedTemplateEntryRestoredInputPointer runtimeTarget
        originalPe caller logicalInput source imageBounded)
  · simpa using
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .esp 28 (by decide)

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_registers_loaded
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).registers =
      (((((((restored.registers.set .eax source.inputAddress).set
        .ebx logicalInput.registers.ebx).set
        .ecx logicalInput.registers.ecx).set
        .esi logicalInput.registers.esi).set
        .edi logicalInput.registers.edi).set
        .ebp logicalInput.registers.ebp).set
        .esp logicalInput.registers.esp) := by
  dsimp only
  rw [nativeX87ReplayFixedTemplateEntryLogicalRegistersState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryEbpLoadedState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryEdiLoadedState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryEsiLoadedState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryEcxLoadedState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryEbxLoadedState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryInputLoadedState_registers
      runtimeTarget originalPe caller logicalInput source imageBounded]

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eax
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).registers.eax =
      source.inputAddress := by
  dsimp only
  have loaded :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_registers_loaded
      runtimeTarget originalPe caller logicalInput source imageBounded
  exact congrArg Registers.eax loaded |>.trans (by
    simp [Registers.set])

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).registers.esp =
      logicalInput.registers.esp := by
  dsimp only
  have loaded :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_registers_loaded
      runtimeTarget originalPe caller logicalInput source imageBounded
  exact congrArg Registers.esp loaded |>.trans (by
    simp [Registers.set])

private theorem nativeX87ReplayLogicalScratchWriteAgreesOutside
    (logicalInput : MachineState) (before : Memory)
    (offset : Nat) (value : Word)
    (inside : offset + 4 <= nativeX87ReplayLogicalScratchBytes) :
    MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (before.write32
        (logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes +
          BitVec.ofNat 32 offset)
        value)
      before := by
  apply MemoryAgreesOutside.write32Inside
  intro byte byteBefore
  refine ⟨offset + byte, by omega, ?_⟩
  simp [nativeX87ReplayLogicalScratchFootprint,
    nativeX87ReplayByteRange, BitVec.add_assoc, ← BitVec.ofNat_add]

private theorem word_sub_four_eq_sub_eight_add_four (value : Word) :
    value - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 8 + BitVec.ofNat 32 4 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem word_sub_four_twice_eq_sub_eight (value : Word) :
    value - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 8 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memoryFrame
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (logicalInput input : MachineState)
    (espExact : input.registers.esp = logicalInput.registers.esp) :
    MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input).memory
      input.memory := by
  let flagsSaved := nativeX87ReplayPushFlagsState input
  let eaxSaved := nativeX87ReplayPushRegState .eax flagsSaved
  have flagsFrame :
      MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
        flagsSaved.memory input.memory := by
    change MemoryAgreesOutside _
      (nativeX87ReplayPushFlagsState input).memory input.memory
    rw [nativeX87ReplayPushFlagsState_memory, espExact,
      word_sub_four_eq_sub_eight_add_four]
    simpa only [nativeX87ReplayLogicalScratchBytes] using
      nativeX87ReplayLogicalScratchWriteAgreesOutside logicalInput input.memory
        4 ((Expr.bitAnd initialSymbolic.eflagsExpression
          (.constant 0xfffcffff)).eval input) (by decide)
  have eaxEsp :
      flagsSaved.registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 := by
    change (nativeX87ReplayPushFlagsState input).registers.esp =
      logicalInput.registers.esp - BitVec.ofNat 32 4
    rw [nativeX87ReplayPushFlagsState_registers, espExact]
    simp [Registers.set]
  have eaxFrame :
      MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
        eaxSaved.memory flagsSaved.memory := by
    change MemoryAgreesOutside _
      (nativeX87ReplayPushRegState .eax flagsSaved).memory flagsSaved.memory
    rw [nativeX87ReplayPushRegState_memory, eaxEsp,
      word_sub_four_twice_eq_sub_eight]
    simpa only [nativeX87ReplayLogicalScratchBytes, BitVec.add_zero] using
      nativeX87ReplayLogicalScratchWriteAgreesOutside logicalInput
        flagsSaved.memory 0 (flagsSaved.registers.get .eax) (by decide)
  have combined := flagsFrame.trans eaxFrame
  change MemoryAgreesOutside _
    (nativeX87ReplayMovFromOperandState .eax
      (nativeX87ReplayMemory none
        ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)))
      eaxSaved).memory input.memory
  rw [nativeX87ReplayMovFromOperandState_memory]
  exact combined

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayPushRegState_top
    (source : Reg) (input : MachineState) :
    Memory.read32
        (nativeX87ReplayPushRegState source input).memory
        (nativeX87ReplayPushRegState source input).registers.esp =
      input.registers.get source := by
  rw [nativeX87ReplayPushRegState_memory,
    nativeX87ReplayPushRegState_registers]
  change
    Memory.read32
        (input.memory.write32
          (input.registers.esp - BitVec.ofNat 32 4)
          (input.registers.get source))
        (input.registers.esp - BitVec.ofNat 32 4) =
      input.registers.get source
  exact Memory.read32_write32_same _ _ _

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayPushFlagsState_top
    (input : MachineState) :
    Memory.read32
        (nativeX87ReplayPushFlagsState input).memory
        (nativeX87ReplayPushFlagsState input).registers.esp =
      ((Expr.bitAnd initialSymbolic.eflagsExpression
        (.constant 0xfffcffff)).eval input) := by
  rw [nativeX87ReplayPushFlagsState_memory,
    nativeX87ReplayPushFlagsState_registers]
  change
    Memory.read32
        (input.memory.write32
          (input.registers.esp - BitVec.ofNat 32 4)
          ((Expr.bitAnd initialSymbolic.eflagsExpression
            (.constant 0xfffcffff)).eval input))
        (input.registers.esp - BitVec.ofNat 32 4) =
      ((Expr.bitAnd initialSymbolic.eflagsExpression
        (.constant 0xfffcffff)).eval input)
  exact Memory.read32_write32_same _ _ _

@[simp] private theorem
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memory
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input).memory =
      (nativeX87ReplayPushRegState .eax
        (nativeX87ReplayPushFlagsState input)).memory := by
  unfold nativeX87ReplayFixedTemplateCaptureBeforeSaveState
  rw [nativeX87ReplayMovFromOperandState_memory]

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayFixedTemplateCaptureBeforeSaveState_esp
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
      input).registers.esp =
      input.registers.esp - BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
  unfold nativeX87ReplayFixedTemplateCaptureBeforeSaveState
  rw [nativeX87ReplayMovFromOperandState_registers,
    nativeX87ReplayPushRegState_registers,
    nativeX87ReplayPushFlagsState_registers]
  change
    input.registers.esp - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
      input.registers.esp - BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes
  simpa only [nativeX87ReplayLogicalScratchBytes] using
    word_sub_four_twice_eq_sub_eight input.registers.esp

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eflags
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe input).eflags =
      input.eflags := by
  unfold nativeX87ReplayFixedTemplateCaptureBeforeSaveState
  rw [nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayPushRegState_eflags,
    nativeX87ReplayPushFlagsState_eflags]

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayCapturePushes_savedFlags
    (input : MachineState) :
    Memory.read32
        (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState input)).memory
        (nativeX87ReplayPushFlagsState input).registers.esp =
      ((Expr.bitAnd initialSymbolic.eflagsExpression
        (.constant 0xfffcffff)).eval input) := by
  rw [nativeX87ReplayPushRegState_memory,
    nativeX87ReplayPushFlagsState_registers,
    nativeX87ReplayPushFlagsState_memory]
  change
    Memory.read32
        ((input.memory.write32
          (input.registers.esp - BitVec.ofNat 32 4)
          ((Expr.bitAnd initialSymbolic.eflagsExpression
            (.constant 0xfffcffff)).eval input)).write32
          (input.registers.esp - BitVec.ofNat 32 4 -
            BitVec.ofNat 32 4) input.registers.eax)
        (input.registers.esp - BitVec.ofNat 32 4) =
      ((Expr.bitAnd initialSymbolic.eflagsExpression
        (.constant 0xfffcffff)).eval input)
  let eaxAddress :=
    input.registers.esp - BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes
  let flagsAddress := input.registers.esp - BitVec.ofNat 32 4
  have eaxAddressExact :
      input.registers.esp - BitVec.ofNat 32 4 - BitVec.ofNat 32 4 =
        eaxAddress := by
    simpa only [eaxAddress, nativeX87ReplayLogicalScratchBytes] using
      word_sub_four_twice_eq_sub_eight input.registers.esp
  rw [eaxAddressExact]
  have eaxFrame :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange eaxAddress 4)
        ((input.memory.write32 flagsAddress
          ((Expr.bitAnd initialSymbolic.eflagsExpression
            (.constant 0xfffcffff)).eval input)).write32
          eaxAddress input.registers.eax)
        (input.memory.write32 flagsAddress
          ((Expr.bitAnd initialSymbolic.eflagsExpression
            (.constant 0xfffcffff)).eval input)) :=
    MemoryAgreesOutside.write32ByteRange _ _ _
  have cellsDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange eaxAddress 4)
        (nativeX87ReplayByteRange flagsAddress 4) := by
    have disjoint := nativeX87ReplayByteRangesDisjoint
      eaxAddress
      0 4 4 4 (by decide) (by decide) (Or.inl (by decide))
    have adjacent :
        eaxAddress + BitVec.ofNat 32 4 = flagsAddress := by
      change
        input.registers.esp - BitVec.ofNat 32 8 + BitVec.ofNat 32 4 =
          input.registers.esp - BitVec.ofNat 32 4
      exact (word_sub_four_eq_sub_eight_add_four
        input.registers.esp).symm
    simpa only [BitVec.add_zero, adjacent] using disjoint
  calc
    _ = Memory.read32
        (input.memory.write32 flagsAddress
          ((Expr.bitAnd initialSymbolic.eflagsExpression
            (.constant 0xfffcffff)).eval input)) flagsAddress :=
      MemoryAgreesOutside.read32_of_disjoint eaxFrame cellsDisjoint
    _ = _ := Memory.read32_write32_same _ _ _

private theorem nativeX87ReplayCapturePushes_savedEax
    (input : MachineState) :
    let flagsSaved := nativeX87ReplayPushFlagsState input
    let eaxSaved := nativeX87ReplayPushRegState .eax flagsSaved
    Memory.read32 eaxSaved.memory eaxSaved.registers.esp =
      input.registers.eax := by
  dsimp only
  calc
    _ = (nativeX87ReplayPushFlagsState input).registers.get .eax :=
      nativeX87ReplayPushRegState_top .eax
        (nativeX87ReplayPushFlagsState input)
    _ = input.registers.eax := by
      rw [nativeX87ReplayPushFlagsState_registers]
      rfl

private theorem
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_memoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored).memory
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).memory := by
  dsimp only
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState
      (nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))
  have espExact : logicalState.registers.esp = logicalInput.registers.esp :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp runtimeTarget
      originalPe caller logicalInput source imageBounded
  rw [nativeX87ReplayFixedTemplateEntryFlagsSavedState,
    nativeX87ReplayPushMemoryEaxState_memory 240 (by decide)]
  change MemoryAgreesOutside _ (logicalState.memory.write32
      (logicalState.registers.esp - BitVec.ofNat 32 4) _) logicalState.memory
  rw [espExact]
  rw [word_sub_four_eq_sub_eight_add_four]
  simpa only [nativeX87ReplayLogicalScratchBytes] using
    nativeX87ReplayLogicalScratchWriteAgreesOutside logicalInput
      logicalState.memory 4
      ((readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) 240)).eval logicalState)
      (by decide)

private theorem
    nativeX87ReplayFixedTemplateEntryEaxSavedState_memoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).memory
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored).memory := by
  dsimp only
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState
      (nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))
  let flagsSaved :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState
      (nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))
  have logicalEsp :
      logicalState.registers.esp = logicalInput.registers.esp :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp runtimeTarget
      originalPe caller logicalInput source imageBounded
  have flagsEsp :
      flagsSaved.registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 := by
    change
      Registers.esp (MachineState.registers
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState
          (nativeX87ReplayFrStorState source.inputCandidate
            (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)))) =
        logicalInput.registers.esp - BitVec.ofNat 32 4
    rw [nativeX87ReplayFixedTemplateEntryFlagsSavedState,
      nativeX87ReplayPushOperandState_esp, logicalEsp]
  rw [nativeX87ReplayFixedTemplateEntryEaxSavedState,
    nativeX87ReplayPushMemoryEaxState_memory 0 (by decide)]
  change MemoryAgreesOutside _ (flagsSaved.memory.write32
      (flagsSaved.registers.esp - BitVec.ofNat 32 4) _) flagsSaved.memory
  rw [flagsEsp]
  rw [word_sub_four_twice_eq_sub_eight]
  simpa only [nativeX87ReplayLogicalScratchBytes, BitVec.add_zero] using
    nativeX87ReplayLogicalScratchWriteAgreesOutside logicalInput
      flagsSaved.memory 0
      ((readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved)
      (by decide)

private theorem
    nativeX87ReplayFixedTemplateEntryScratchMemoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).memory
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).memory := by
  dsimp only
  exact
    (nativeX87ReplayFixedTemplateEntryFlagsSavedState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
    (nativeX87ReplayFixedTemplateEntryEaxSavedState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded)

private theorem nativeX87ReplayLogicalScratchDisjointRequiredField
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (field : Engine.EngineField) (offset : Nat)
    (required : field ∈ source.rep.layout.requiredFields)
    (canonical : nativeX87ReplayEngineFieldOffset? field = some offset) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (nativeX87ReplayByteRange
        (source.outputAddress + BitVec.ofNat 32 offset) field.byteWidth) := by
  rcases source.engineRelated.repValid.1 with
    ⟨_stateSizePositive, _stateSizeBound, _fieldsNodup, _fieldsValid,
      _fieldsDisjoint, fieldsComplete⟩
  rcases List.mem_map.mp (fieldsComplete field required) with
    ⟨entry, entryMember, entryField⟩
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  have entryOffset := List.all_eq_true.mp layout.1.2 entry entryMember
  simp only [entryField, canonical, beq_iff_eq, Option.some.injEq] at entryOffset
  intro address scratchMember fieldMember
  apply source.replayScratchDisjointRepresentation address scratchMember
  apply Or.inl
  rcases fieldMember with ⟨byte, byteBefore, rfl⟩
  refine ⟨entry, entryMember, byte, ?_, ?_⟩
  · simpa [entryField] using byteBefore
  · simp [Engine.EngineFieldLayout.address, entryOffset, source.engineBase,
      BitVec.add_assoc]

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_registers
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryFlagsSavedState input).registers =
      { (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input).registers
        with
        esp :=
          Registers.esp (MachineState.registers
            (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input)) -
              BitVec.ofNat 32 4 } := by
  exact nativeX87ReplayPushMemoryEaxState_registers 240 (by decide) _

private theorem nativeX87ReplayFixedTemplateEntryFlagsSavedState_top_of_read
    (input : MachineState) (base value : Word)
    (baseExact :
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState
        input).registers.eax = base)
    (valueExact :
      Memory.read32
          (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input).memory
          (base + BitVec.ofNat 32 240) =
        value) :
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState input).memory
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState input).registers.esp =
      value := by
  have baseGet :
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState
        input).registers.get .eax = base := by
    simpa [Registers.get] using baseExact
  unfold nativeX87ReplayFixedTemplateEntryFlagsSavedState
  exact nativeX87ReplayPushMemoryEaxState_top_of_read 240 (by decide)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input)
    base value baseGet valueExact

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEaxSavedState_registers
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEaxSavedState input).registers =
      { (nativeX87ReplayFixedTemplateEntryFlagsSavedState input).registers
        with
        esp :=
          Registers.esp (MachineState.registers
            (nativeX87ReplayFixedTemplateEntryFlagsSavedState input)) -
              BitVec.ofNat 32 4 } := by
  exact nativeX87ReplayPushMemoryEaxState_registers 0 (by decide) _

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEaxSavedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEaxSavedState input).memory =
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState input).memory.write32
        ((nativeX87ReplayFixedTemplateEntryFlagsSavedState
          input).registers.esp - BitVec.ofNat 32 4)
        ((readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) 0)).eval
            (nativeX87ReplayFixedTemplateEntryFlagsSavedState input)) := by
  exact nativeX87ReplayPushMemoryEaxState_memory 0 (by decide) _

private theorem nativeX87ReplayFixedTemplateEntryEaxSavedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryEaxSavedState
      input).registers.eax = inputAddress := by
  rw [nativeX87ReplayFixedTemplateEntryEaxSavedState_registers,
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_registers]
  simpa using eaxExact

private theorem nativeX87ReplayFixedTemplateEntryFlagsSavedState_eax
    (input : MachineState) (inputAddress : Word)
    (eaxExact :
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState
        input).registers.eax = inputAddress) :
    (nativeX87ReplayFixedTemplateEntryFlagsSavedState
      input).registers.eax = inputAddress := by
  rw [nativeX87ReplayFixedTemplateEntryFlagsSavedState_registers]
  simpa using eaxExact

private theorem nativeX87ReplayFixedTemplateEntryFlagsSavedState_esp
    (input : MachineState) (logicalEsp : Word)
    (espExact :
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState
        input).registers.esp = logicalEsp) :
    (nativeX87ReplayFixedTemplateEntryFlagsSavedState
      input).registers.esp =
      logicalEsp - BitVec.ofNat 32 4 := by
  rw [nativeX87ReplayFixedTemplateEntryFlagsSavedState_registers, espExact]

private theorem nativeX87ReplayFixedTemplateEntryEaxSavedState_esp
    (input : MachineState) (logicalEsp : Word)
    (espExact :
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState
        input).registers.esp = logicalEsp) :
    (nativeX87ReplayFixedTemplateEntryEaxSavedState
      input).registers.esp =
      logicalEsp - BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
  rw [nativeX87ReplayFixedTemplateEntryEaxSavedState_registers,
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_registers, espExact]
  exact word_sub_four_twice_eq_sub_eight logicalEsp

private theorem
    nativeX87ReplayFixedTemplateEntryEaxSavedState_memoryAtOwnEsp
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEaxSavedState input).memory =
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState input).memory.write32
        (nativeX87ReplayFixedTemplateEntryEaxSavedState input).registers.esp
        ((readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) 0)).eval
            (nativeX87ReplayFixedTemplateEntryFlagsSavedState input)) := by
  let flagsSaved := nativeX87ReplayFixedTemplateEntryFlagsSavedState input
  have raw :=
    nativeX87ReplayPushMemoryEaxState_memory 0 (by decide) flagsSaved
  have writeAddress :
      flagsSaved.registers.esp - BitVec.ofNat 32 4 =
        (nativeX87ReplayFixedTemplateEntryEaxSavedState input).registers.esp := by
    exact (nativeX87ReplayPushOperandState_esp
      (nativeX87ReplayMemory (some .eax) 0) flagsSaved).symm
  exact raw.trans (congrArg
    (fun address =>
      flagsSaved.memory.write32 address
        ((readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved))
    writeAddress)

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEdxLoadedState input).memory =
      (nativeX87ReplayFixedTemplateEntryEaxSavedState input).memory := by
  unfold nativeX87ReplayFixedTemplateEntryEdxLoadedState
  exact nativeX87ReplayMovFromOperandState_memory .edx _ _

@[simp] private theorem
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_memory
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState input).memory =
      (nativeX87ReplayFixedTemplateEntryEdxLoadedState input).memory := by
  unfold nativeX87ReplayFixedTemplateEntryEaxRestoredState
  exact nativeX87ReplayPopRegState_memory .eax _

private theorem
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_eflags
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState input).eflags =
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input).eflags := by
  unfold nativeX87ReplayFixedTemplateEntryEaxRestoredState
    nativeX87ReplayFixedTemplateEntryEdxLoadedState
    nativeX87ReplayFixedTemplateEntryEaxSavedState
    nativeX87ReplayFixedTemplateEntryFlagsSavedState
  rw [nativeX87ReplayPopRegState_eflags,
    nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayPushOperandState_eflags,
    nativeX87ReplayPushOperandState_eflags]

private theorem
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_readInputRegisterAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (register : Reg) (offset : Nat)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.register register) = some offset) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored).memory
        (source.inputAddress + BitVec.ofNat 32 offset) =
      logicalInput.registers.get register := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let flagsSaved := nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
  have required :
      Engine.EngineField.register register ∈
        source.rep.layout.requiredFields := by
    cases register <;>
      simp [Engine.EngineLayout.requiredFields, Engine.allRegisters]
  have scratchFrame :
      MemoryAgreesOutside
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        flagsSaved.memory logicalState.memory :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded
  have disjointOutput :=
    nativeX87ReplayLogicalScratchDisjointRequiredField source
      (Engine.EngineField.register register) offset required canonical
  have disjointInput :
      CandidateFootprintsDisjoint
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayByteRange
          (source.inputAddress + BitVec.ofNat 32 offset) 4) := by
    simpa [source.inputOutputAlias] using disjointOutput
  calc
    Memory.read32 flagsSaved.memory
        (source.inputAddress + BitVec.ofNat 32 offset) =
      Memory.read32 logicalState.memory
        (source.inputAddress + BitVec.ofNat 32 offset) :=
      memoryAgreesOutside_read32_of_disjoint scratchFrame disjointInput
    _ = Memory.read32 restored.memory
        (source.inputAddress + BitVec.ofNat 32 offset) := by
      exact congrArg
        (fun memory => Memory.read32 memory
          (source.inputAddress + BitVec.ofNat 32 offset))
        (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory restored)
    _ = logicalInput.registers.get register :=
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        register offset canonical

private theorem
    nativeX87ReplayFixedTemplateEntryEaxSavedState_readInputRegisterAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (register : Reg) (offset : Nat)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.register register) = some offset) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).memory
        (source.inputAddress + BitVec.ofNat 32 offset) =
      logicalInput.registers.get register := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let eaxSaved := nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  have required :
      Engine.EngineField.register register ∈
        source.rep.layout.requiredFields := by
    cases register <;>
      simp [Engine.EngineLayout.requiredFields, Engine.allRegisters]
  have scratchFrame :
      MemoryAgreesOutside
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        eaxSaved.memory logicalState.memory :=
    nativeX87ReplayFixedTemplateEntryScratchMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  have disjointOutput :=
    nativeX87ReplayLogicalScratchDisjointRequiredField source
      (Engine.EngineField.register register) offset required canonical
  have disjointInput :
      CandidateFootprintsDisjoint
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayByteRange
          (source.inputAddress + BitVec.ofNat 32 offset) 4) := by
    simpa [source.inputOutputAlias] using disjointOutput
  calc
    Memory.read32 eaxSaved.memory
        (source.inputAddress + BitVec.ofNat 32 offset) =
      Memory.read32 logicalState.memory
        (source.inputAddress + BitVec.ofNat 32 offset) :=
      memoryAgreesOutside_read32_of_disjoint scratchFrame disjointInput
    _ = Memory.read32 restored.memory
        (source.inputAddress + BitVec.ofNat 32 offset) := by
      exact congrArg
        (fun memory => Memory.read32 memory
          (source.inputAddress + BitVec.ofNat 32 offset))
        (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory restored)
    _ = logicalInput.registers.get register :=
      nativeX87ReplayFixedTemplateEntryRestoredReadInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        register offset canonical

private theorem nativeX87ReplayPushMemoryEaxState_top
    (displacement : Nat)
    (distinct :
      readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) displacement) ≠
        .read32
          (initialSymbolic.registers.esp.offset (2 ^ 32 - 4)))
    (input : MachineState) (value : Word)
    (sourceValue :
      (readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) displacement)).eval input = value)
    (stackValid :
      (input.registers.esp - BitVec.ofNat 32 4).toNat + 4 <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayPushOperandState
          (nativeX87ReplayMemory (some .eax) displacement) input).memory
        (nativeX87ReplayPushOperandState
          (nativeX87ReplayMemory (some .eax) displacement) input).registers.esp =
      value := by
  rw [nativeX87ReplayPushMemoryEaxState_memory displacement distinct,
    nativeX87ReplayPushOperandState_esp,
    Memory.read32_write32_same_of_fits _ _ _ stackValid, sourceValue]

private theorem nativeX87ReplayFixedTemplateEntryEaxSavedState_top_of_value
    (input : MachineState) (value : Word)
    (sourceValue :
      (readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) 0)).eval
          (nativeX87ReplayFixedTemplateEntryFlagsSavedState input) = value)
    (stackValid :
      ((nativeX87ReplayFixedTemplateEntryFlagsSavedState input).registers.esp -
        BitVec.ofNat 32 4).toNat + 4 <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryEaxSavedState input).memory
        (nativeX87ReplayFixedTemplateEntryEaxSavedState input).registers.esp =
      value :=
  nativeX87ReplayPushMemoryEaxState_top 0 (by decide)
    (nativeX87ReplayFixedTemplateEntryFlagsSavedState input) value
    sourceValue stackValid

private theorem nativeX87ReplayMemoryEaxZero_eval_of_read
    (input : MachineState) (address value : Word)
    (eax : input.registers.eax = address)
    (read : Memory.read32 input.memory address = value) :
    (readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) 0)).eval input = value := by
  rw [readNativeX87ReplayMemorySome]
  simp only [Registers.get, eax, BitVec.add_zero]
  exact read

private theorem
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_savedEax
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) 0)).eval
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored) =
      logicalInput.registers.eax := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let flagsSaved := nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
  have logicalEax : logicalState.registers.eax = source.inputAddress :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eax runtimeTarget
      originalPe caller logicalInput source imageBounded
  have flagsEax : flagsSaved.registers.eax = source.inputAddress :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_eax restored
      source.inputAddress logicalEax
  have read :
      Memory.read32 flagsSaved.memory source.inputAddress =
        logicalInput.registers.eax := by
    simpa only [BitVec.add_zero, Registers.get] using
      nativeX87ReplayFixedTemplateEntryFlagsSavedState_readInputRegisterAtOffset
        runtimeTarget originalPe caller logicalInput source imageBounded
        .eax 0 (by decide)
  exact nativeX87ReplayMemoryEaxZero_eval_of_read flagsSaved
    source.inputAddress logicalInput.registers.eax flagsEax read

private theorem
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_stackWriteValid
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    let flagsSaved :=
      nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
    (flagsSaved.registers.esp - BitVec.ofNat 32 4).toNat + 4 <=
      2 ^ 32 := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let flagsSaved := nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
  have logicalEsp : logicalState.registers.esp = logicalInput.registers.esp :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp runtimeTarget
      originalPe caller logicalInput source imageBounded
  have flagsEsp :
      flagsSaved.registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_esp restored
      logicalInput.registers.esp logicalEsp
  rw [flagsEsp, word_sub_four_twice_eq_sub_eight]
  have scratchValid := source.replayScratchAddressValid
  change
    (logicalInput.registers.esp - BitVec.ofNat 32 8).toNat + 8 <=
      2 ^ 32 at scratchValid
  omega

private theorem nativeX87ReplayFixedTemplateEntryEaxSavedState_top
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).memory
        (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).registers.esp =
      logicalInput.registers.eax := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let flagsSaved := nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
  have savedValue :
      (readOperand32 initialSymbolic
          (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved =
        logicalInput.registers.eax := by
    exact
      nativeX87ReplayFixedTemplateEntryFlagsSavedState_savedEax runtimeTarget
        originalPe caller logicalInput source imageBounded
  have stackValid :
      (flagsSaved.registers.esp - BitVec.ofNat 32 4).toNat + 4 <=
        2 ^ 32 := by
    exact
      nativeX87ReplayFixedTemplateEntryFlagsSavedState_stackWriteValid
        runtimeTarget originalPe caller logicalInput source imageBounded
  exact nativeX87ReplayFixedTemplateEntryEaxSavedState_top_of_value restored
    logicalInput.registers.eax savedValue stackValid

private theorem
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEdxLoadedState restored).registers =
      (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).registers.set
        .edx logicalInput.registers.edx := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  have logicalEax :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eax runtimeTarget
      originalPe caller logicalInput source imageBounded
  have eaxSavedEax :
      (nativeX87ReplayFixedTemplateEntryEaxSavedState
        restored).registers.eax = source.inputAddress :=
    nativeX87ReplayFixedTemplateEntryEaxSavedState_eax restored
      source.inputAddress logicalEax
  apply nativeX87ReplayMovFromEaxMemoryState_registers .edx 12 _
    source.inputAddress logicalInput.registers.edx eaxSavedEax
  simpa using
    nativeX87ReplayFixedTemplateEntryEaxSavedState_readInputRegisterAtOffset
      runtimeTarget originalPe caller logicalInput source imageBounded
      .edx 12 (by decide)

private theorem word_sub_eight_add_four_eq_sub_four (value : Word) :
    value - BitVec.ofNat 32 8 + BitVec.ofNat 32 4 =
      value - BitVec.ofNat 32 4 := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem word_sub_four_add_four_eq (value : Word) :
    value - BitVec.ofNat 32 4 + BitVec.ofNat 32 4 = value := by
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

private theorem
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_registers_compact
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEdxLoadedState restored).registers =
      { logicalInput.registers with
          eax := source.inputAddress
          esp := logicalInput.registers.esp -
            BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes } := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  rw [nativeX87ReplayFixedTemplateEntryEdxLoadedState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded,
    nativeX87ReplayFixedTemplateEntryEaxSavedState_registers,
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_registers,
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_registers_loaded
      runtimeTarget originalPe caller logicalInput source imageBounded]
  apply Registers.eq_of_fields <;>
    simp [Registers.set, nativeX87ReplayLogicalScratchBytes,
      word_sub_four_twice_eq_sub_eight]

private theorem
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_top
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryEdxLoadedState restored).memory
        (nativeX87ReplayFixedTemplateEntryEdxLoadedState restored).registers.esp =
      logicalInput.registers.eax := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let eaxSaved := nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  let edxLoaded := nativeX87ReplayFixedTemplateEntryEdxLoadedState restored
  have memoryExact : edxLoaded.memory = eaxSaved.memory := by
    exact nativeX87ReplayMovFromOperandState_memory .edx _ eaxSaved
  have registersExact :=
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_registers_compact runtimeTarget
      originalPe caller logicalInput source imageBounded
  have espExact : edxLoaded.registers.esp = eaxSaved.registers.esp := by
    calc
      _ = logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
        exact congrArg Registers.esp registersExact |>.trans (by
          simp)
      _ = eaxSaved.registers.esp := by
        symm
        exact
          nativeX87ReplayFixedTemplateEntryEaxSavedState_esp restored
            logicalInput.registers.esp
            (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp
              runtimeTarget originalPe caller logicalInput source imageBounded)
  rw [memoryExact, espExact]
  exact
    nativeX87ReplayFixedTemplateEntryEaxSavedState_top runtimeTarget originalPe
      caller logicalInput source imageBounded

private theorem
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState restored).registers =
      { logicalInput.registers with
          esp := logicalInput.registers.esp - BitVec.ofNat 32 4 } := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  have edxRegisters :=
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_registers_compact runtimeTarget
      originalPe caller logicalInput source imageBounded
  have edxTop :=
    nativeX87ReplayFixedTemplateEntryEdxLoadedState_top runtimeTarget originalPe
      caller logicalInput source imageBounded
  rw [nativeX87ReplayFixedTemplateEntryEaxRestoredState,
    nativeX87ReplayPopRegState_registers, edxTop, edxRegisters]
  apply Registers.eq_of_fields <;>
    simp [Registers.set, nativeX87ReplayLogicalScratchBytes,
      word_sub_eight_add_four_eq_sub_four]

private theorem
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryFlagsRestoredState restored).registers =
      logicalInput.registers := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  rw [nativeX87ReplayFixedTemplateEntryFlagsRestoredState,
    nativeX87ReplayPopFlagsState_registers,
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded]
  apply Registers.eq_of_fields <;>
    simp [Registers.set, word_sub_four_add_four_eq]

private theorem nativeX87ReplayFixedTemplateInstructionEntryState_registers
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller).registers = logicalInput.registers := by
  unfold nativeX87ReplayFixedTemplateInstructionEntryState
    nativeX87ReplayFixedTemplateEntrySuffixState
  rw [nativeX87ReplayNopState_registers]
  exact
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded

private theorem
    nativeX87ReplayEntrySavedState_eflags
    (returnAddress : Nat) (caller : MachineState) :
    (nativeX87ReplayEntrySavedState returnAddress caller).eflags =
      caller.eflags := by
  unfold nativeX87ReplayEntrySavedState
  rw [nativeX87ReplayPushRegState_eflags,
    nativeX87ReplayPushRegState_eflags,
    nativeX87ReplayPushRegState_eflags,
    nativeX87ReplayPushRegState_eflags]
  change ordinaryInstructionInitialFlags caller = caller.eflags
  exact initialSymbolicFlags_eval caller

private theorem
    nativeX87ReplayFixedTemplateEntryStoredState_eflags
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (caller : MachineState) :
    (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).eflags =
      caller.eflags := by
  unfold nativeX87ReplayFixedTemplateEntryStoredState
    nativeX87ReplayFixedTemplateEntryLoadedState
  rw [nativeX87ReplayMovToMemoryState_eflags,
    nativeX87ReplayMovFromOperandState_eflags]
  exact nativeX87ReplayEntrySavedState_eflags
    (pe.imageBase + table.continuationRva) caller

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eflags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored).eflags =
      caller.eflags := by
  dsimp only
  unfold nativeX87ReplayFixedTemplateEntryLogicalRegistersState
    nativeX87ReplayFixedTemplateEntryEbpLoadedState
    nativeX87ReplayFixedTemplateEntryEdiLoadedState
    nativeX87ReplayFixedTemplateEntryEsiLoadedState
    nativeX87ReplayFixedTemplateEntryEcxLoadedState
    nativeX87ReplayFixedTemplateEntryEbxLoadedState
    nativeX87ReplayFixedTemplateEntryInputLoadedState
  rw [nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayMovFromOperandState_eflags,
    nativeX87ReplayMovFromOperandState_eflags]
  rw [nativeX87ReplayFrStorState_eflags]
  exact nativeX87ReplayFixedTemplateEntryStoredState_eflags table pe caller

private theorem nativeX87ReplaySavedStackCellPreserved
    (flagsSaved eaxSaved edxLoaded eaxRestored : MachineState)
    (value writeValue : Word)
    (flagsTop :
      Memory.read32 flagsSaved.memory flagsSaved.registers.esp = value)
    (eaxMemory :
      eaxSaved.memory =
        flagsSaved.memory.write32 eaxSaved.registers.esp writeValue)
    (scratchDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange eaxSaved.registers.esp 4)
        (nativeX87ReplayByteRange flagsSaved.registers.esp 4))
    (loadedMemory : edxLoaded.memory = eaxSaved.memory)
    (restoredMemory : eaxRestored.memory = edxLoaded.memory)
    (restoredEsp :
      eaxRestored.registers.esp = flagsSaved.registers.esp) :
    Memory.read32 eaxRestored.memory eaxRestored.registers.esp = value := by
  have flagsPreserved :
      Memory.read32 eaxSaved.memory flagsSaved.registers.esp =
        Memory.read32 flagsSaved.memory flagsSaved.registers.esp := by
    rw [eaxMemory]
    exact MemoryAgreesOutside.read32_of_disjoint
      (MemoryAgreesOutside.write32ByteRange flagsSaved.memory
        eaxSaved.registers.esp writeValue)
      scratchDisjoint
  calc
    Memory.read32 eaxRestored.memory eaxRestored.registers.esp =
        Memory.read32 eaxSaved.memory flagsSaved.registers.esp := by
      rw [restoredMemory, loadedMemory, restoredEsp]
    _ = Memory.read32 flagsSaved.memory flagsSaved.registers.esp :=
      flagsPreserved
    _ = value := flagsTop

private theorem nativeX87ReplayCpl3PopFlagsRestores
    (caller logicalInput eaxRestored : MachineState)
    (current : eaxRestored.eflags = caller.eflags)
    (popped :
      Memory.read32 eaxRestored.memory eaxRestored.registers.esp =
        logicalInput.eflags)
    (checked : cpl3PopFlagsSourceFrameChecked caller logicalInput.eflags = true) :
    (nativeX87ReplayNopState 3
      (nativeX87ReplayPopFlagsState eaxRestored)).eflags =
      logicalInput.eflags := by
  rw [nativeX87ReplayNopState_eflags,
    nativeX87ReplayPopFlagsState_eflags, popped]
  have expressionExact :
      (popFlagsCpl3Expression initialSymbolic.eflagsExpression
        (.constant logicalInput.eflags.toNat)).eval eaxRestored =
      (popFlagsCpl3Expression initialSymbolic.eflagsExpression
        (.constant logicalInput.eflags.toNat)).eval caller := by
    apply popFlagsCpl3Expression_eval_congr
    · rw [initialSymbolicEflagsExpression_eval,
        initialSymbolicEflagsExpression_eval, current]
    · rfl
  exact expressionExact.trans
    (cpl3PopFlagsSourceFrameChecked_restores caller logicalInput.eflags checked)

/-
private theorem nativeX87ReplayFixedTemplateInstructionEntryState_eflags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller).eflags = logicalInput.eflags := by
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let flagsSaved :=
    nativeX87ReplayPushOperandState
      (nativeX87ReplayMemory (some .eax) 240) logicalState
  let eaxSaved :=
    nativeX87ReplayPushOperandState
      (nativeX87ReplayMemory (some .eax) 0) flagsSaved
  let edxLoaded :=
    nativeX87ReplayMovFromOperandState .edx
      (nativeX87ReplayMemory (some .eax) 12) eaxSaved
  let eaxRestored :=
    nativeX87ReplayPopRegState .eax edxLoaded
  let wrappedFlagsSaved :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
  let wrappedEaxSaved :=
    nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  let wrappedEdxLoaded :=
    nativeX87ReplayFixedTemplateEntryEdxLoadedState restored
  let wrappedEaxRestored :=
    nativeX87ReplayFixedTemplateEntryEaxRestoredState restored
  have wrappedFlagsExact : wrappedFlagsSaved = flagsSaved := by
    exact nativeX87ReplayFixedTemplateEntryFlagsSavedState_eq restored
  have wrappedEaxExact : wrappedEaxSaved = eaxSaved := by
    exact (nativeX87ReplayFixedTemplateEntryEaxSavedState_eq restored).trans
      (congrArg
        (nativeX87ReplayPushOperandState
          (nativeX87ReplayMemory (some .eax) 0))
        wrappedFlagsExact)
  have wrappedEdxExact : wrappedEdxLoaded = edxLoaded := by
    exact (nativeX87ReplayFixedTemplateEntryEdxLoadedState_eq restored).trans
      (congrArg
        (nativeX87ReplayMovFromOperandState .edx
          (nativeX87ReplayMemory (some .eax) 12))
        wrappedEaxExact)
  have wrappedEaxRestoredExact : wrappedEaxRestored = eaxRestored := by
    exact (nativeX87ReplayFixedTemplateEntryEaxRestoredState_eq restored).trans
      (congrArg (nativeX87ReplayPopRegState .eax) wrappedEdxExact)
  have logicalEax : logicalState.registers.get .eax = source.inputAddress := by
    simpa [Registers.get] using
      nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eax runtimeTarget
        originalPe caller logicalInput source imageBounded
  have logicalMemory : logicalState.memory = restored.memory :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory restored
  have sourceValue :
      Memory.read32 logicalState.memory
          (source.inputAddress + BitVec.ofNat 32 240) =
        logicalInput.eflags := by
    calc
      _ = Memory.read32 restored.memory
          (source.inputAddress + BitVec.ofNat 32 240) :=
        congrArg
          (fun memory => Memory.read32 memory
            (source.inputAddress + BitVec.ofNat 32 240))
          logicalMemory
      _ = logicalInput.eflags :=
        nativeX87ReplayFixedTemplateEntryRestoredReadInputEflags runtimeTarget
          originalPe caller logicalInput source imageBounded
  have flagsTop :
      Memory.read32 flagsSaved.memory flagsSaved.registers.esp =
        logicalInput.eflags := by
    exact nativeX87ReplayPushMemoryEaxState_top_of_read 240 (by decide)
      logicalState source.inputAddress logicalInput.eflags logicalEax sourceValue
  have logicalEsp : logicalState.registers.esp = logicalInput.registers.esp :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp runtimeTarget
      originalPe caller logicalInput source imageBounded
  have flagsEsp :
      flagsSaved.registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 := by
    rw [nativeX87ReplayPushOperandState_esp, logicalEsp]
  have eaxEsp :
      eaxSaved.registers.esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
    rw [nativeX87ReplayPushOperandState_esp, flagsEsp]
    simpa [nativeX87ReplayLogicalScratchBytes] using
      word_sub_four_twice_eq_sub_eight logicalInput.registers.esp
  have restoredEsp : eaxRestored.registers.esp = flagsSaved.registers.esp := by
    have edxEsp : edxLoaded.registers.esp = eaxSaved.registers.esp := by
      simpa [Registers.get] using
        nativeX87ReplayMovFromOperandState_register_other .edx .esp
          (nativeX87ReplayMemory (some .eax) 12) eaxSaved (by decide)
    have popEsp :
        eaxRestored.registers.esp =
          edxLoaded.registers.esp + BitVec.ofNat 32 4 := by
      rw [nativeX87ReplayPopRegState_registers]
      simp [eaxRestored, Registers.set]
    calc
      eaxRestored.registers.esp =
          edxLoaded.registers.esp + BitVec.ofNat 32 4 := popEsp
      _ = eaxSaved.registers.esp + BitVec.ofNat 32 4 :=
        congrArg (fun value => value + BitVec.ofNat 32 4) edxEsp
      _ = (logicalInput.registers.esp - BitVec.ofNat 32 8) +
          BitVec.ofNat 32 4 := by
        rw [eaxEsp]
        rfl
      _ = logicalInput.registers.esp - BitVec.ofNat 32 4 :=
        word_sub_eight_add_four_eq_sub_four logicalInput.registers.esp
      _ = flagsSaved.registers.esp := flagsEsp.symm
  have eaxMemory :
      eaxSaved.memory =
        flagsSaved.memory.write32 eaxSaved.registers.esp
          ((readOperand32 initialSymbolic
            (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved) := by
    have raw :=
      nativeX87ReplayPushMemoryEaxState_memory 0 (by decide) flagsSaved
    have writeAddress :
        flagsSaved.registers.esp - BitVec.ofNat 32 4 =
          eaxSaved.registers.esp := by
      exact (nativeX87ReplayPushOperandState_esp
        (nativeX87ReplayMemory (some .eax) 0) flagsSaved).symm
    exact raw.trans (congrArg
      (fun address =>
        flagsSaved.memory.write32 address
          ((readOperand32 initialSymbolic
            (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved))
      writeAddress)
  have scratchDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange eaxSaved.registers.esp 4)
        (nativeX87ReplayByteRange flagsSaved.registers.esp 4) := by
    intro address eaxMember flagsMember
    have disjoint :=
      nativeX87ReplayByteRangesDisjoint
        (logicalInput.registers.esp - BitVec.ofNat 32 8)
        0 4 4 4
        (by
          simpa [nativeX87ReplayLogicalScratchBytes] using
            source.replayScratchAddressValid)
        (by
          simpa [nativeX87ReplayLogicalScratchBytes] using
            source.replayScratchAddressValid)
        (Or.inl (by omega))
    apply disjoint address
    · simpa [eaxEsp, nativeX87ReplayLogicalScratchBytes] using eaxMember
    · simpa [flagsEsp,
        word_sub_eight_add_four_eq_sub_four] using flagsMember
  have popped :
      Memory.read32 eaxRestored.memory eaxRestored.registers.esp =
        logicalInput.eflags := by
    apply nativeX87ReplaySavedStackCellPreserved flagsSaved eaxSaved edxLoaded
      eaxRestored logicalInput.eflags
      ((readOperand32 initialSymbolic
        (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved)
      flagsTop eaxMemory scratchDisjoint
    · exact nativeX87ReplayMovFromOperandState_memory .edx _ eaxSaved
    · exact nativeX87ReplayPopRegState_memory .eax edxLoaded
    · exact restoredEsp
  have current :
      eaxRestored.eflags = caller.eflags := by
    unfold eaxRestored edxLoaded eaxSaved flagsSaved
    rw [nativeX87ReplayPopRegState_eflags,
      nativeX87ReplayMovFromOperandState_eflags,
      nativeX87ReplayPushOperandState_eflags,
      nativeX87ReplayPushOperandState_eflags]
    exact nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eflags
      runtimeTarget originalPe caller logicalInput source imageBounded
  calc
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).eflags =
        (nativeX87ReplayFixedTemplateEntrySuffixState restored).eflags :=
      congrArg MachineState.eflags
        (nativeX87ReplayFixedTemplateInstructionEntryState_eq table pe
          source.inputCandidate caller)
    _ = (nativeX87ReplayNopState 3
        (nativeX87ReplayPopFlagsState wrappedEaxRestored)).eflags :=
      congrArg MachineState.eflags
        (nativeX87ReplayFixedTemplateEntrySuffixState_eq restored)
    _ = (nativeX87ReplayNopState 3
        (nativeX87ReplayPopFlagsState eaxRestored)).eflags :=
      congrArg
        (fun state =>
          (nativeX87ReplayNopState 3
            (nativeX87ReplayPopFlagsState state)).eflags)
        wrappedEaxRestoredExact
    _ = logicalInput.eflags :=
      nativeX87ReplayCpl3PopFlagsRestores caller logicalInput eaxRestored
        current popped source.popFlagsCpl3
-/

set_option maxHeartbeats 1000 in
private theorem
    nativeX87ReplayFixedTemplateEntryLogicalStateReadInputEflags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    let logicalState :=
      nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
    Memory.read32 logicalState.memory
        (source.inputAddress + BitVec.ofNat 32 240) =
      logicalInput.eflags := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  have logicalMemory : logicalState.memory = restored.memory :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory restored
  calc
    _ = Memory.read32 restored.memory
        (source.inputAddress + BitVec.ofNat 32 240) :=
      congrArg
        (fun memory => Memory.read32 memory
          (source.inputAddress + BitVec.ofNat 32 240))
        logicalMemory
    _ = logicalInput.eflags :=
      nativeX87ReplayFixedTemplateEntryRestoredReadInputEflags runtimeTarget
        originalPe caller logicalInput source imageBounded

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayFixedTemplateEntryFlagsSavedTop
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    let flagsSaved :=
      nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
    Memory.read32 flagsSaved.memory flagsSaved.registers.esp =
      logicalInput.eflags := by
  dsimp only
  exact nativeX87ReplayFixedTemplateEntryFlagsSavedState_top_of_read
    (nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))
    source.inputAddress logicalInput.eflags
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eax runtimeTarget
      originalPe caller logicalInput source imageBounded)
    (nativeX87ReplayFixedTemplateEntryLogicalStateReadInputEflags runtimeTarget
      originalPe caller logicalInput source imageBounded)

private theorem
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_esp_eq_flagsSaved
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState restored).registers.esp =
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored).registers.esp := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  have logicalEsp :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp runtimeTarget
      originalPe caller logicalInput source imageBounded
  have flagsEsp :
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored).registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_esp restored
      logicalInput.registers.esp logicalEsp
  have restoredRegisters :=
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded
  have restoredEsp :
      (nativeX87ReplayFixedTemplateEntryEaxRestoredState restored).registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 :=
    congrArg Registers.esp restoredRegisters |>.trans (by simp)
  exact restoredEsp.trans flagsEsp.symm

private theorem
    nativeX87ReplayFixedTemplateEntrySavedCellsDisjoint
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    CandidateFootprintsDisjoint
      (nativeX87ReplayByteRange
        (nativeX87ReplayFixedTemplateEntryEaxSavedState
          restored).registers.esp 4)
      (nativeX87ReplayByteRange
        (nativeX87ReplayFixedTemplateEntryFlagsSavedState
          restored).registers.esp 4) := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  have logicalEsp :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_esp runtimeTarget
      originalPe caller logicalInput source imageBounded
  have flagsEsp :
      (nativeX87ReplayFixedTemplateEntryFlagsSavedState restored).registers.esp =
        logicalInput.registers.esp - BitVec.ofNat 32 4 :=
    nativeX87ReplayFixedTemplateEntryFlagsSavedState_esp restored
      logicalInput.registers.esp logicalEsp
  have eaxEsp :
      (nativeX87ReplayFixedTemplateEntryEaxSavedState restored).registers.esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes :=
    nativeX87ReplayFixedTemplateEntryEaxSavedState_esp restored
      logicalInput.registers.esp logicalEsp
  intro address eaxMember flagsMember
  have disjoint :=
    nativeX87ReplayByteRangesDisjoint
      (logicalInput.registers.esp - BitVec.ofNat 32 8)
      0 4 4 4
      (by
        simpa [nativeX87ReplayLogicalScratchBytes] using
          source.replayScratchAddressValid)
      (by
        simpa [nativeX87ReplayLogicalScratchBytes] using
          source.replayScratchAddressValid)
      (Or.inl (by omega))
  apply disjoint address
  · rw [eaxEsp] at eaxMember
    simpa [nativeX87ReplayLogicalScratchBytes, BitVec.add_zero] using eaxMember
  · rw [flagsEsp] at flagsMember
    simpa only [word_sub_eight_add_four_eq_sub_four] using flagsMember

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayFixedTemplateEntryEaxRestoredTop
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    let eaxRestored :=
      nativeX87ReplayFixedTemplateEntryEaxRestoredState restored
    Memory.read32 eaxRestored.memory eaxRestored.registers.esp =
      logicalInput.eflags := by
  dsimp only
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let flagsSaved := nativeX87ReplayFixedTemplateEntryFlagsSavedState restored
  let eaxSaved := nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  let edxLoaded := nativeX87ReplayFixedTemplateEntryEdxLoadedState restored
  let eaxRestored := nativeX87ReplayFixedTemplateEntryEaxRestoredState restored
  exact nativeX87ReplaySavedStackCellPreserved
    flagsSaved eaxSaved edxLoaded eaxRestored logicalInput.eflags
    ((readOperand32 initialSymbolic
      (nativeX87ReplayMemory (some .eax) 0)).eval flagsSaved)
    (nativeX87ReplayFixedTemplateEntryFlagsSavedTop runtimeTarget originalPe
      caller logicalInput source imageBounded)
    (nativeX87ReplayFixedTemplateEntryEaxSavedState_memoryAtOwnEsp restored)
    (nativeX87ReplayFixedTemplateEntrySavedCellsDisjoint runtimeTarget originalPe
      caller logicalInput source imageBounded)
    (nativeX87ReplayFixedTemplateEntryEdxLoadedState_memory restored)
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState_memory restored)
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState_esp_eq_flagsSaved
      runtimeTarget originalPe caller logicalInput source imageBounded)

private theorem
    nativeX87ReplayFixedTemplateEntryEaxRestoredState_currentEflags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    let restored :=
      nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState restored).eflags =
      caller.eflags := by
  dsimp only
  exact
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState_eflags
      (nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))).trans
      (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_eflags
        runtimeTarget originalPe caller logicalInput source imageBounded)

set_option maxHeartbeats 5000 in
private theorem nativeX87ReplayFixedTemplateInstructionEntryState_eflags_exact
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller).eflags = logicalInput.eflags := by
  unfold nativeX87ReplayFixedTemplateInstructionEntryState
    nativeX87ReplayFixedTemplateEntrySuffixState
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState
  exact nativeX87ReplayCpl3PopFlagsRestores caller logicalInput
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState
      (nativeX87ReplayFrStorState source.inputCandidate
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)))
    (nativeX87ReplayFixedTemplateEntryEaxRestoredState_currentEflags
      runtimeTarget originalPe caller logicalInput source imageBounded)
    (nativeX87ReplayFixedTemplateEntryEaxRestoredTop runtimeTarget originalPe
      caller logicalInput source imageBounded)
    source.popFlagsCpl3

private theorem
    nativeX87ReplayFixedTemplateEntryPreparationDisjointOperand
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFixedTemplateEntryPreparationFootprint source)
      (nativeX87ReplayOperandFootprint source.commandInput.candidateDescriptor
        source.candidateInput) := by
  intro address preparationMember operandMember
  rcases preparationMember with privateMember | frameMember
  · exact source.privateStackDisjointOperand address privateMember operandMember
  · apply source.frameDisjointOperand address
    · rcases frameMember with ⟨byte, byteBefore, rfl⟩
      exact ⟨nativeX87FramePrivateEspOffset + byte, by
        simp [nativeX87ReplayFrameBytes, nativeX87FramePrivateEspOffset,
          nativeX87FrameOutputX87Offset, kernelX87FrameBytes]
        omega, by
        simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
    · exact operandMember

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_memory
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (inputCandidate : StageA.X87.PhysicalState) (caller : MachineState) :
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe
      inputCandidate caller).memory =
      (nativeX87ReplayFixedTemplateEntryEaxSavedState
        (nativeX87ReplayFrStorState inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))).memory := by
  unfold nativeX87ReplayFixedTemplateInstructionEntryState
    nativeX87ReplayFixedTemplateEntrySuffixState
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState
    nativeX87ReplayFixedTemplateEntryEaxRestoredState
    nativeX87ReplayFixedTemplateEntryEdxLoadedState
  rw [nativeX87ReplayNopState_memory, nativeX87ReplayPopFlagsState_memory,
    nativeX87ReplayPopRegState_memory,
    nativeX87ReplayMovFromOperandState_memory]

private def nativeX87ReplayFixedTemplateEntryAfterSaveFootprint
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) : CandidateFootprint :=
  footprintUnion
    (nativeX87ReplayByteRange
      (source.frameAddress +
        BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4)
    (nativeX87ReplayLogicalScratchFootprint logicalInput)

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryAfterStoredFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    MemoryAgreesOutside
      (nativeX87ReplayLogicalScratchFootprint logicalInput)
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).memory
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory := by
  let stored := nativeX87ReplayFixedTemplateEntryStoredState table pe caller
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate stored
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let eaxSaved :=
    nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  have scratchFrame :
      MemoryAgreesOutside
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        eaxSaved.memory logicalState.memory :=
    nativeX87ReplayFixedTemplateEntryScratchMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  intro address outside
  calc
    _ = eaxSaved.memory address :=
      congrArg (fun memory => memory address)
        (nativeX87ReplayFixedTemplateInstructionEntryState_memory table pe
          source.inputCandidate caller)
    _ = logicalState.memory address := scratchFrame address outside
    _ = restored.memory address := by
      exact congrArg (fun memory => memory address)
        (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory
          restored)
    _ = stored.memory address := rfl

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryAfterSavedFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    MemoryAgreesOutside
      (nativeX87ReplayFixedTemplateEntryAfterSaveFootprint source)
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller).memory
        (nativeX87ReplayEntrySavedState
          (pe.imageBase + table.continuationRva) caller).memory := by
  let saved := nativeX87ReplayEntrySavedState
    (pe.imageBase + table.continuationRva) caller
  let loaded := nativeX87ReplayFixedTemplateEntryLoadedState table pe caller
  let stored := nativeX87ReplayFixedTemplateEntryStoredState table pe caller
  have loadedEax :
      loaded.registers.get .eax = source.frameAddress := by
    simpa [loaded, Registers.get] using
      nativeX87ReplayFixedTemplateEntryLoadedEax runtimeTarget originalPe
        caller logicalInput source imageBounded
  have storedMemory :
      stored.memory =
        loaded.memory.write32
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset)
          loaded.registers.esp := by
    change stored.memory =
      loaded.memory.write32
        (source.frameAddress + BitVec.ofNat 32 12) loaded.registers.esp
    rw [show stored.memory =
        loaded.memory.write32
          (((nativeX87ReplayAddressing (some .eax) 12).expression
            initialSymbolic.registers).eval loaded)
          (loaded.registers.get .esp) by
      simpa [stored, nativeX87ReplayFixedTemplateEntryStoredState, loaded] using
        nativeX87ReplayMovToMemoryState_memory
          (nativeX87ReplayAddressing (some .eax) 12) .esp loaded]
    rw [nativeX87ReplayAddressing_some_eval, loadedEax]
    rfl
  have storedToLoaded :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4)
        stored.memory loaded.memory := by
    rw [storedMemory]
    exact MemoryAgreesOutside.write32ByteRange loaded.memory
      (source.frameAddress +
        BitVec.ofNat 32 nativeX87FramePrivateEspOffset)
      loaded.registers.esp
  have storedToSaved :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4)
        stored.memory saved.memory := by
    intro address outside
    exact (storedToLoaded address outside).trans
      (congrArg (fun memory => memory address)
        (nativeX87ReplayFixedTemplateEntryLoadedState_memory table pe caller))
  have instructionToStored :
      MemoryAgreesOutside
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller).memory
        stored.memory :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryAfterStoredFrame
      runtimeTarget originalPe caller logicalInput source imageBounded
  exact MemoryAgreesOutside.compose storedToSaved instructionToStored

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_returnAddress
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller).memory
        (nativeX87ReplayPrivateStackByte caller 16) =
      BitVec.ofNat 32 (pe.imageBase + table.continuationRva) := by
  have frame :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryAfterSavedFrame
      runtimeTarget originalPe caller logicalInput source imageBounded
  have disjointReturn :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateEntryAfterSaveFootprint source)
        (nativeX87ReplayByteRange
          (nativeX87ReplayPrivateStackByte caller 16) 4) := by
    intro address entryMember returnMember
    have privateMember :
        nativeX87ReplayPrivateStackFootprint caller address := by
      exact (by
        simpa [nativeX87ReplayPrivateStackByte] using
          nativeX87ReplayPrivateStackByteRange_subset caller 16 4 (by decide)
            address returnMember)
    rcases entryMember with frameMember | scratchMember
    · exact source.privateStackDisjointFrame address privateMember
        (nativeX87ReplayFrameByteRange_subset source.frameAddress
          nativeX87FramePrivateEspOffset 4 (by decide) address frameMember)
    · exact source.replayScratchDisjointPrivateStack address scratchMember
        privateMember
  calc
    _ = Memory.read32
        (nativeX87ReplayEntrySavedState
          (pe.imageBase + table.continuationRva) caller).memory
        (nativeX87ReplayPrivateStackByte caller 16) :=
      MemoryAgreesOutside.read32_of_disjoint frame disjointReturn
    _ = BitVec.ofNat 32 (pe.imageBase + table.continuationRva) :=
      nativeX87ReplayEntrySavedState_returnAddress
        (pe.imageBase + table.continuationRva) caller
        source.privateStackAddressValid

private theorem
    nativeX87ReplayFixedTemplateEntryStoredState_privateStackPointer
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
      caller.registers.esp - BitVec.ofNat 32 20 := by
  let loaded := nativeX87ReplayFixedTemplateEntryLoadedState table pe caller
  have loadedEax :
      loaded.registers.get .eax = source.frameAddress := by
    simpa [loaded, Registers.get] using
      nativeX87ReplayFixedTemplateEntryLoadedEax runtimeTarget originalPe
        caller logicalInput source imageBounded
  have loadedEsp :
      loaded.registers.esp =
        caller.registers.esp - BitVec.ofNat 32 20 := by
    calc
      loaded.registers.esp =
          (nativeX87ReplayEntrySavedState
            (pe.imageBase + table.continuationRva) caller).registers.esp := by
        simpa [loaded, Registers.get] using
          nativeX87ReplayMovFromOperandState_register_other .eax .esp
            (nativeX87ReplayMemory none
              ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)))
            (nativeX87ReplayEntrySavedState
              (pe.imageBase + table.continuationRva) caller) (by decide)
      _ = caller.registers.esp - BitVec.ofNat 32 20 :=
        nativeX87ReplayEntrySavedState_esp
          (pe.imageBase + table.continuationRva) caller
  rw [show
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory =
        loaded.memory.write32
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset)
          loaded.registers.esp by
    change _ = loaded.memory.write32
      (source.frameAddress + BitVec.ofNat 32 12) loaded.registers.esp
    rw [show
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory =
          loaded.memory.write32
            (((nativeX87ReplayAddressing (some .eax) 12).expression
              initialSymbolic.registers).eval loaded)
            (loaded.registers.get .esp) by
      simpa [loaded, nativeX87ReplayFixedTemplateEntryStoredState] using
        nativeX87ReplayMovToMemoryState_memory
          (nativeX87ReplayAddressing (some .eax) 12) .esp loaded]
    rw [nativeX87ReplayAddressing_some_eval, loadedEax]
    rfl]
  rw [Memory.read32_write32_same, loadedEsp]

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_privateStackPointer
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    Memory.read32
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller).memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
      caller.registers.esp - BitVec.ofNat 32 20 := by
  have frame :
      MemoryAgreesOutside
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller).memory
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryAfterStoredFrame
      runtimeTarget originalPe caller logicalInput source imageBounded
  have scratchDisjointPrivateEsp :
      CandidateFootprintsDisjoint
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4) := by
    exact CandidateFootprintsDisjoint.mono
      source.replayScratchDisjointFrame
      (fun _ member => member)
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FramePrivateEspOffset 4 (by decide))
  calc
    _ = Memory.read32
        (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) :=
      MemoryAgreesOutside.read32_of_disjoint frame
        scratchDisjointPrivateEsp
    _ = caller.registers.esp - BitVec.ofNat 32 20 :=
      nativeX87ReplayFixedTemplateEntryStoredState_privateStackPointer
        runtimeTarget originalPe caller logicalInput source imageBounded

private def nativeX87ReplayFixedTemplateEntryWriteFootprint
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) : CandidateFootprint :=
  fun address =>
    nativeX87ReplayFixedTemplateEntryPreparationFootprint source address ∨
      nativeX87ReplayLogicalScratchFootprint logicalInput address

private theorem nativeX87ReplayFixedTemplateEntryWriteDisjointImage
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List
      (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {originalPe : PE32} {caller logicalInput : MachineState}
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintDisjointFromImage pe
      (nativeX87ReplayFixedTemplateEntryWriteFootprint source) := by
  intro address member
  rcases member with preparation | scratch
  · rcases preparation with privateStack | privateEsp
    · exact source.privateStackDisjointImage address privateStack
    · apply source.frameDisjointImage address
      rcases privateEsp with ⟨byte, byteBefore, rfl⟩
      exact ⟨nativeX87FramePrivateEspOffset + byte, by
        simp [nativeX87ReplayFrameBytes, nativeX87FramePrivateEspOffset,
          nativeX87FrameOutputX87Offset, kernelX87FrameBytes]
        omega, by
        simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
  · exact source.replayScratchDisjointImage address scratch

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    MemoryAgreesOutside
      (nativeX87ReplayFixedTemplateEntryWriteFootprint source)
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).memory
      caller.memory := by
  intro address outside
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let eaxSaved := nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  have instructionMemory :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memory table pe
      source.inputCandidate caller
  have scratchFrame :
      MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
        eaxSaved.memory logicalState.memory :=
    nativeX87ReplayFixedTemplateEntryScratchMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  have preparationFrame :=
    nativeX87ReplayFixedTemplateEntryStoredMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  calc
    _ = eaxSaved.memory address :=
      congrArg (fun memory => memory address) instructionMemory
    _ = logicalState.memory address :=
      scratchFrame address (fun member => outside (Or.inr member))
    _ = restored.memory address := by
      exact congrArg (fun memory => memory address)
        (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory restored)
    _ = (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory
          address := rfl
    _ = caller.memory address :=
      preparationFrame address (fun member => outside (Or.inl member))

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryOnOperand
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    ∀ address,
      nativeX87ReplayOperandFootprint source.commandInput.candidateDescriptor
          source.candidateInput address ->
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller).memory address =
          source.candidateInput.memory address := by
  intro address operandMember
  let restored :=
    nativeX87ReplayFrStorState source.inputCandidate
      (nativeX87ReplayFixedTemplateEntryStoredState table pe caller)
  let logicalState :=
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState restored
  let eaxSaved := nativeX87ReplayFixedTemplateEntryEaxSavedState restored
  have instructionMemory :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memory table pe
      source.inputCandidate caller
  have scratchFrame :
      MemoryAgreesOutside (nativeX87ReplayLogicalScratchFootprint logicalInput)
        eaxSaved.memory logicalState.memory :=
    nativeX87ReplayFixedTemplateEntryScratchMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  have preparationFrame :=
    nativeX87ReplayFixedTemplateEntryStoredMemoryFrame runtimeTarget originalPe
      caller logicalInput source imageBounded
  have scratchOutside :
      ¬ nativeX87ReplayLogicalScratchFootprint logicalInput address := by
    intro scratchMember
    exact source.replayScratchDisjointOperand address scratchMember operandMember
  have preparationOutside :
      ¬ nativeX87ReplayFixedTemplateEntryPreparationFootprint source address := by
    intro preparationMember
    exact nativeX87ReplayFixedTemplateEntryPreparationDisjointOperand source
      address preparationMember operandMember
  calc
    _ = eaxSaved.memory address := congrArg (fun memory => memory address)
      instructionMemory
    _ = logicalState.memory address := scratchFrame address scratchOutside
    _ = restored.memory address := by
      exact congrArg (fun memory => memory address)
        (nativeX87ReplayFixedTemplateEntryLogicalRegistersState_memory restored)
    _ = (nativeX87ReplayFixedTemplateEntryStoredState table pe caller).memory
          address := rfl
    _ = caller.memory address := preparationFrame address preparationOutside
    _ = source.candidateInput.memory address := by
      rw [source.candidateMemory]

@[simp] private theorem nativeX87ReplayNopState_x87Physical
    (count : Nat) (input : MachineState) :
    (nativeX87ReplayNopState count input).x87Physical =
      input.x87Physical := by
  induction count generalizing input with
  | zero => rfl
  | succ count induction =>
      simp only [nativeX87ReplayNopState]
      rw [induction]
      exact nativeX87ReplayOrdinaryState_x87Physical initialSymbolic input

@[simp] private theorem nativeX87ReplayNopState_x87Semantics
    (count : Nat) (input : MachineState) :
    (nativeX87ReplayNopState count input).x87Semantics =
      input.x87Semantics := by
  induction count generalizing input with
  | zero => rfl
  | succ count induction =>
      simp only [nativeX87ReplayNopState]
      rw [induction]
      exact nativeX87ReplayOrdinaryState_x87Semantics initialSymbolic input

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_x87Physical
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input).x87Physical =
      input.x87Physical := by
  unfold nativeX87ReplayFixedTemplateEntryLogicalRegistersState
    nativeX87ReplayFixedTemplateEntryEbpLoadedState
    nativeX87ReplayFixedTemplateEntryEdiLoadedState
    nativeX87ReplayFixedTemplateEntryEsiLoadedState
    nativeX87ReplayFixedTemplateEntryEcxLoadedState
    nativeX87ReplayFixedTemplateEntryEbxLoadedState
    nativeX87ReplayFixedTemplateEntryInputLoadedState
  repeat rw [nativeX87ReplayMovFromOperandState_x87Physical]

private theorem
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_x87Semantics
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntryLogicalRegistersState input).x87Semantics =
      input.x87Semantics := by
  unfold nativeX87ReplayFixedTemplateEntryLogicalRegistersState
    nativeX87ReplayFixedTemplateEntryEbpLoadedState
    nativeX87ReplayFixedTemplateEntryEdiLoadedState
    nativeX87ReplayFixedTemplateEntryEsiLoadedState
    nativeX87ReplayFixedTemplateEntryEcxLoadedState
    nativeX87ReplayFixedTemplateEntryEbxLoadedState
    nativeX87ReplayFixedTemplateEntryInputLoadedState
  repeat rw [nativeX87ReplayMovFromOperandState_x87Semantics]

private theorem nativeX87ReplayFixedTemplateEntrySuffixState_x87Physical
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntrySuffixState input).x87Physical =
      input.x87Physical := by
  unfold nativeX87ReplayFixedTemplateEntrySuffixState
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState
    nativeX87ReplayFixedTemplateEntryEaxRestoredState
    nativeX87ReplayFixedTemplateEntryEdxLoadedState
    nativeX87ReplayFixedTemplateEntryEaxSavedState
    nativeX87ReplayFixedTemplateEntryFlagsSavedState
  rw [nativeX87ReplayNopState_x87Physical,
    nativeX87ReplayPopFlagsState_x87Physical,
    nativeX87ReplayPopRegState_x87Physical,
    nativeX87ReplayMovFromOperandState_x87Physical,
    nativeX87ReplayPushOperandState_x87Physical,
    nativeX87ReplayPushOperandState_x87Physical]
  exact
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_x87Physical input

private theorem nativeX87ReplayFixedTemplateEntrySuffixState_x87Semantics
    (input : MachineState) :
    (nativeX87ReplayFixedTemplateEntrySuffixState input).x87Semantics =
      input.x87Semantics := by
  unfold nativeX87ReplayFixedTemplateEntrySuffixState
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState
    nativeX87ReplayFixedTemplateEntryEaxRestoredState
    nativeX87ReplayFixedTemplateEntryEdxLoadedState
    nativeX87ReplayFixedTemplateEntryEaxSavedState
    nativeX87ReplayFixedTemplateEntryFlagsSavedState
  rw [nativeX87ReplayNopState_x87Semantics,
    nativeX87ReplayPopFlagsState_x87Semantics,
    nativeX87ReplayPopRegState_x87Semantics,
    nativeX87ReplayMovFromOperandState_x87Semantics,
    nativeX87ReplayPushOperandState_x87Semantics,
    nativeX87ReplayPushOperandState_x87Semantics]
  exact
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState_x87Semantics input

/-- The post-`FRSTOR` entry suffix is total for every machine state.  This
state-parametric lemma is deliberately separate from source-frame admission,
so the kernel checks a short linear role chain rather than one nested proof. -/
private theorem nativeX87ReplayFixedTemplateEntryRoles_afterRestore_running
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (input : MachineState) :
    runNativeX87ReplayTemplateRoles pe imports 7 input
        ((nativeX87ReplayFixedTemplateEntryRoles table pe
          runtimeTarget.target.frameMapping).drop 7) =
      .running runtimeTarget.target.frameMapping.instructionRva 22
        (nativeX87ReplayFixedTemplateEntrySuffixState input) := by
  have instructionRvaExact :
      runtimeTarget.target.frameMapping.instructionRva =
        runtimeTarget.target.frameMapping.bridgeTargetRva +
          nativeX87ReplayBridgeInstructionOffset := by
    by_cases exact :
        runtimeTarget.target.frameMapping.instructionRva =
          runtimeTarget.target.frameMapping.bridgeTargetRva +
            nativeX87ReplayBridgeInstructionOffset
    · exact exact
    · have checked := runtimeTarget.target.frameMappingChecked
      simp [NativeX87ReplayBridgeFrameMapping.checked, exact] at checked
  simp only [nativeX87ReplayFixedTemplateEntryRoles,
    nativeX87ReplayOrdinaryRole, nativeX87ReplayMemory, List.drop]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_pushOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_movFromOperand
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (source := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_popReg
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (destination := _)
      (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_popFlags
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_nop
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  rw [runNativeX87ReplayTemplateRoles_cons_running
    (NativeX87ReplayTemplateRole.semanticStep_nop
      (pe := pe) (imports := imports)
      (rva := _) (size := _) (undefinedSlot := _) (input := _))
    (by simp [NativeX87ReplayTemplateRole.rva])]
  simp [runNativeX87ReplayTemplateRoles,
    NativeX87ReplayTemplateRole.rva, instructionRvaExact,
    nativeX87ReplayBridgeInstructionOffset,
    NativeX87ReplayTemplateRole.semanticStep_nop,
    nativeX87ReplayFixedTemplateEntrySuffixState,
    nativeX87ReplayFixedTemplateEntryFlagsRestoredState,
    nativeX87ReplayFixedTemplateEntryEaxRestoredState,
    nativeX87ReplayFixedTemplateEntryEdxLoadedState,
    nativeX87ReplayFixedTemplateEntryEaxSavedState,
    nativeX87ReplayFixedTemplateEntryFlagsSavedState,
    nativeX87ReplayFixedTemplateEntryLogicalRegistersState,
    nativeX87ReplayFixedTemplateEntryEbpLoadedState,
    nativeX87ReplayFixedTemplateEntryEdiLoadedState,
    nativeX87ReplayFixedTemplateEntryEsiLoadedState,
    nativeX87ReplayFixedTemplateEntryEcxLoadedState,
    nativeX87ReplayFixedTemplateEntryEbxLoadedState,
    nativeX87ReplayFixedTemplateEntryInputLoadedState,
    nativeX87ReplayNopState, nativeX87ReplayMemory,
    nativeX87FrameInputOffset]

/-- Diagnostic execution boundary for the complete fixed entry path.  The
source-frame prefix and total suffix are independently checked opaque facts. -/
private theorem nativeX87ReplayFixedTemplateEntryRoles_running
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    runNativeX87ReplayTemplateRoles pe imports 0
        (indirectCallEntryState
          (pe.imageBase + table.continuationRva) caller)
        (nativeX87ReplayFixedTemplateEntryRoles table pe
          runtimeTarget.target.frameMapping) =
      .running runtimeTarget.target.frameMapping.instructionRva 22
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller) := by
  have prefixExact :=
    nativeX87ReplayFixedTemplateEntryRoles_afterRestore runtimeTarget
      originalPe caller logicalInput source imageBounded
  have suffixExact :=
    nativeX87ReplayFixedTemplateEntryRoles_afterRestore_running
      runtimeTarget
        (nativeX87ReplayFrStorState source.inputCandidate
          (nativeX87ReplayFixedTemplateEntryStoredState table pe caller))
  simpa [nativeX87ReplayFixedTemplateInstructionEntryState] using
    prefixExact.trans suffixExact

private theorem exactNativeX87ReplayFixedTemplateEntryRun
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (programBinding :
      ExactNativeX87ReplayKernelProgramBinding inventory program)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (calls : List NativeCallFrame) :
    runRelatedSteps
        program.transitionSystem
        static.schedule.entryFuel
        (.running runtimeTarget.target.descriptor.bridge.entry.rva 0
          (indirectCallEntryState
            (program.pe.imageBase + table.continuationRva) caller)
          calls 0 [] RelationalWorld.empty []) =
      (.running runtimeTarget.target.frameMapping.instructionRva
        static.schedule.entryFuel
        (nativeX87ReplayFixedTemplateInstructionEntryState table program.pe
          source.inputCandidate caller)
        calls 0 [] RelationalWorld.empty [], []) := by
  have peExact := programBinding.peExact
  have importsExact := programBinding.importsExact
  subst pe
  subst imports
  have rolesExact := static.semanticShape.entry
  have phaseLength :=
    kernelMixedReplayTemplateRoles?_length static.mixedReplay.entry
      (nativeX87ReplayFixedTemplateEntryRoles table program.pe
        runtimeTarget.target.frameMapping) rolesExact
  have fuelExact :
      static.schedule.entryFuel =
        (nativeX87ReplayFixedTemplateEntryRoles table program.pe
          runtimeTarget.target.frameMapping).length :=
    static.entryFuelExact.trans phaseLength
  have executed :=
    nativeX87ReplayFixedTemplateEntryRoles_running runtimeTarget originalPe
      caller logicalInput source programBinding.imageBounded
  cases entriesExact : static.mixedReplay.entry with
  | nil =>
      have impossible := rolesExact
      simp [entriesExact, kernelMixedReplayTemplateRoles?,
        nativeX87ReplayFixedTemplateEntryRoles] at impossible
  | cons first tail =>
      have firstRva := kernelMixedReplayTemplateRoles?_head_rva first tail
        (.ordinary runtimeTarget.target.frameMapping.bridgeTargetRva
          (.pushReg .ebp) 1)
        (nativeX87ReplayFixedTemplateEntryRoles table program.pe
          runtimeTarget.target.frameMapping).tail
        (by
          simpa [entriesExact, nativeX87ReplayFixedTemplateEntryRoles] using
            rolesExact)
      have firstRvaExact :
          first.instruction.rva =
            runtimeTarget.target.descriptor.bridge.entry.rva := by
        have bridgeExact :
            runtimeTarget.target.frameMapping.bridgeTargetRva =
              runtimeTarget.target.descriptor.bridge.entry.rva := by
          by_cases exact :
              runtimeTarget.target.frameMapping.bridgeTargetRva =
                runtimeTarget.target.descriptor.bridge.entry.rva
          · exact exact
          · have checked := runtimeTarget.target.frameMappingChecked
            simp [NativeX87ReplayBridgeFrameMapping.checked, exact] at checked
        simpa [nativeX87ReplayFixedTemplateEntryRoles,
          NativeX87ReplayTemplateRole.rva, bridgeExact] using firstRva
      have phase :=
        exactNativeX87ReplayPhaseRun_of_roles program
          static.mixedReplay.entry first tail entriesExact
          (nativeX87ReplayFixedTemplateEntryRoles table program.pe
            runtimeTarget.target.frameMapping)
          rolesExact 0 static.mixedReplay.entry.length
          runtimeTarget.target.frameMapping.instructionRva
          (indirectCallEntryState
            (program.pe.imageBase + table.continuationRva) caller)
          (nativeX87ReplayFixedTemplateInstructionEntryState table program.pe
            source.inputCandidate caller)
          calls (by simpa [phaseLength] using executed)
      rw [static.entryFuelExact, ← firstRvaExact]
      exact phase

private theorem exactNativeX87ReplayFixedTemplateEntryEndpoint_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (programBinding :
      ExactNativeX87ReplayKernelProgramBinding inventory program)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (calls : List NativeCallFrame) :
    (exactNativeX87ReplaySilentRunningEndpoint?
      (runRelatedSteps
        program.transitionSystem
        static.schedule.entryFuel
        (.running runtimeTarget.target.descriptor.bridge.entry.rva 0
          (indirectCallEntryState
            (program.pe.imageBase + table.continuationRva) caller)
          calls 0 [] RelationalWorld.empty []))
      runtimeTarget.target.frameMapping.instructionRva
      static.schedule.entryFuel calls).isSome = true := by
  rw [exactNativeX87ReplayFixedTemplateEntryRun runtimeTarget static inventory
    program programBinding originalPe caller logicalInput source calls]
  simp [exactNativeX87ReplaySilentRunningEndpoint?]

@[simp] private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_x87Physical
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (inputCandidate : StageA.X87.PhysicalState)
    (caller : MachineState) :
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe inputCandidate
      caller).x87Physical = inputCandidate := by
  unfold nativeX87ReplayFixedTemplateInstructionEntryState
  rw [nativeX87ReplayFixedTemplateEntrySuffixState_x87Physical]
  exact nativeX87ReplayFrStorState_x87Physical _ _

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_x87Semantics
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).x87Semantics =
      source.candidateInput.x87Semantics := by
  calc
    _ = caller.x87Semantics := by
      unfold nativeX87ReplayFixedTemplateInstructionEntryState
      rw [nativeX87ReplayFixedTemplateEntrySuffixState_x87Semantics]
      rw [nativeX87ReplayFrStorState_x87Semantics]
      exact nativeX87ReplayFixedTemplateEntryStoredState_x87Semantics _ _ _
    _ = source.rep.x87Semantics := source.callerSemantics
    _ = source.candidateInput.x87Semantics :=
      source.engineRelated.candidateSemantics.symm

/-- Once the fixed bridge has restored the source-frame x87 state, command
inputs, and shared semantics, the generic parametric x87 theorem constructs the
executable physical-state check. No architectural floating-point result is
assumed or computed by this bridge theorem. -/
theorem exactNativeX87ReplaySingletonPhysicalStatesChecked
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (candidateExecutionInput : MachineState)
    (candidatePhysicalInput :
      candidateExecutionInput.x87Physical =
        source.candidateInput.x87Physical)
    (candidateCommandInput :
      StageA.Relational.X87.commandStepInput pe
          runtimeTarget.addressMap.candidateInstructionRva
          source.commandInput.candidateDescriptor candidateExecutionInput =
        StageA.Relational.X87.commandStepInput pe
          runtimeTarget.addressMap.candidateInstructionRva
          source.commandInput.candidateDescriptor source.candidateInput)
    (candidateSemantics :
      candidateExecutionInput.x87Semantics =
        source.candidateInput.x87Semantics)
    (originalResult candidateResult : StepResult)
    (originalExecuted :
      executeX87Singleton originalPe
          (replayInstructionRecord runtimeTarget.target.descriptor.replay)
          logicalInput =
        some originalResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt
            runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          candidateExecutionInput =
        some candidateResult) :
    nativeX87ReplayPhysicalStatesRelatedChecked runtimeTarget.addressMap
        originalResult.state.x87Physical
        candidateResult.state.x87Physical =
      true := by
  let commandInput :
      X87SingletonCommandInputRelated runtimeTarget.addressMap.relation
        originalPe pe
        (replayInstructionRecord runtimeTarget.target.descriptor.replay)
        (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
          runtimeTarget.addressMap.candidateInstructionRva)
        logicalInput candidateExecutionInput := {
    originalDescriptor := source.commandInput.originalDescriptor
    candidateDescriptor := source.commandInput.candidateDescriptor
    originalDecoded := source.commandInput.originalDecoded
    candidateDecoded := source.commandInput.candidateDecoded
    commandExact := source.commandInput.commandExact
    waitModeExact := source.commandInput.waitModeExact
    inputs := by
      change StageA.Relational.X87.InputRelated
        runtimeTarget.addressMap.relation
        (StageA.Relational.X87.commandStepInput originalPe
          runtimeTarget.target.descriptor.replay.rvaStart
          source.commandInput.originalDescriptor logicalInput)
        (StageA.Relational.X87.commandStepInput pe
          runtimeTarget.addressMap.candidateInstructionRva
          source.commandInput.candidateDescriptor candidateExecutionInput)
      rw [candidateCommandInput]
      simpa [replayInstructionRecord, replayInstructionRecordAt] using
        source.commandInput.inputs
  }
  have states :
      StageA.Relational.X87.StateRelated runtimeTarget.addressMap.relation
        logicalInput.x87Physical candidateExecutionInput.x87Physical := by
    rw [candidatePhysicalInput, source.candidateX87]
    exact source.inputFrame.related
  have semantics :
      logicalInput.x87Semantics = candidateExecutionInput.x87Semantics :=
    source.engineRelated.shared_x87_semantics.trans candidateSemantics.symm
  exact nativeX87ReplayPhysicalStatesRelatedChecked_complete
    runtimeTarget.addressMap originalResult.state.x87Physical
    candidateResult.state.x87Physical
    (executeX87Singleton_state_related runtimeTarget.addressMap.relation
      originalPe pe
      (replayInstructionRecord runtimeTarget.target.descriptor.replay)
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      logicalInput candidateExecutionInput originalResult candidateResult
      commandInput states semantics originalExecuted candidateExecuted)

private def nativeX87ReplaySingletonMemoryAddress
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (input : MachineState) (response : StageA.X87.Response) : Option Word :=
  match response.store with
  | none => none
  | some _ => StageA.Relational.X87.commandDataAddress descriptor input

/-- The singleton witness exposes the data address selected by the exact
command executor.  This is kept separate from response equivalence because
memory-effect pairing needs both facts. -/
private theorem nativeX87ReplaySingletonMemoryAddress_exact
    {candidatePe : PE32} {record : RawInstructionRecord}
    {input : MachineState} {result : StepResult}
    (witness : X87SingletonExecutionWitness candidatePe record input result) :
    witness.effect.memoryAddress =
      nativeX87ReplaySingletonMemoryAddress witness.descriptor input
        witness.effect.response := by
  have executed := witness.executed
  unfold StageA.Relational.X87.executeSingletonCommand at executed
  rw [witness.decoded] at executed
  simp [normalizeCodeTarget, singletonTarget] at executed
  split at executed
  · rcases executed with ⟨_, _, _, behaviorExact⟩
    have behaviorExact := Option.some.inj behaviorExact
    have effectBound := witness.effectBound
    rw [← behaviorExact] at effectBound
    simp [StageA.Relational.X87.singletonBehavior] at effectBound
    rw [← effectBound]
    simp_all [nativeX87ReplaySingletonMemoryAddress]
  · rcases executed with ⟨_, _, _, executed⟩
    cases addressExact :
        StageA.Relational.X87.commandDataAddress witness.descriptor input with
    | none => simp [addressExact] at executed
    | some address =>
        simp [addressExact] at executed
        have behaviorExact := executed
        have effectBound := witness.effectBound
        rw [← behaviorExact] at effectBound
        simp [StageA.Relational.X87.singletonBehavior] at effectBound
        rw [← effectBound]
        simp_all [nativeX87ReplaySingletonMemoryAddress, addressExact]

private theorem memoryAgreesOutside_writeX87BitsInside
    (footprint : CandidateFootprint) (before : Memory)
    (address : Word) (bits : BitVec 80) (count : Nat)
    (inside : ∀ offset, offset < count ->
      footprint (address + BitVec.ofNat 32 offset)) :
    MemoryAgreesOutside footprint
      (Memory.writeX87Bits before address bits count) before := by
  induction count with
  | zero =>
      exact MemoryAgreesOutside.refl footprint before
  | succ count induction =>
      have prefixFrame :
          MemoryAgreesOutside footprint
            (Memory.writeX87Bits before address bits count) before :=
        induction (fun offset offsetBefore =>
          inside offset (Nat.lt_succ_of_lt offsetBefore))
      have finalByte :
          MemoryAgreesOutside footprint
            (Memory.write8
              (Memory.writeX87Bits before address bits count)
              (address + BitVec.ofNat 32 count)
              (bits.extractLsb' (count * 8) 8))
            (Memory.writeX87Bits before address bits count) := by
        intro query outside
        unfold Memory.write8
        rw [if_neg]
        intro equal
        exact outside (equal ▸ inside count (Nat.lt_succ_self count))
      simpa only [Memory.writeX87Bits] using prefixFrame.trans finalByte

/-- A successful singleton may update physical x87 state, AX, EFLAGS, and one
decoded memory operand.  Its concrete memory is therefore framed by the
source-independent operand footprint recovered from exact decoding. -/
private theorem executeX87Singleton_memoryFrame
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    let witness :=
      executeX87Singleton_witness candidatePe record input result executed
    MemoryAgreesOutside
      (nativeX87ReplayOperandFootprint witness.descriptor input)
      result.state.memory input.memory := by
  dsimp only
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  change MemoryAgreesOutside
    (nativeX87ReplayOperandFootprint witness.descriptor input)
    result.state.memory input.memory
  have ran := witness.executed
  unfold StageA.Relational.X87.executeSingletonCommand at ran
  rw [witness.decoded] at ran
  simp [normalizeCodeTarget, singletonTarget] at ran
  have responseExact := witness.responseExecution
  rw [← responseExact] at ran
  cases storeExact : witness.effect.response.store with
  | none =>
    simp only [storeExact] at ran
    rcases ran with ⟨_, _, _, behaviorExact⟩
    have behaviorExact := Option.some.inj behaviorExact
    rw [witness.resultState, ← behaviorExact]
    simp [StageA.Relational.X87.singletonBehavior,
      RelationalBehavior.nextMachineState, applyX87MemoryEffect, storeExact]
    exact MemoryAgreesOutside.refl _ _
  | some store =>
    simp only [storeExact] at ran
    rcases ran with ⟨_, _, _, ran⟩
    cases addressExact :
        StageA.Relational.X87.commandDataAddress witness.descriptor input with
    | none => simp [addressExact] at ran
    | some address =>
        simp [addressExact] at ran
        have behaviorExact := ran
        have structurallyValid :=
          input.x87Semantics.execute_structurallyValid
            input.x87Semantics.complies witness.descriptor.command
            witness.descriptor.waitMode input.x87Physical
            (StageA.Relational.X87.commandStepInput candidatePe
              record.span.start witness.descriptor input)
            (StageA.Relational.X87.decodeSingletonCommand_waitModeValid
              candidatePe record.span witness.descriptor witness.decoded)
            (StageA.Relational.X87.commandStepInput_valid candidatePe
              record.span.start witness.descriptor input)
        have expectedStore :
            witness.descriptor.command.expectedStoreKind =
              some store.kind := by
          unfold StageA.X87.Response.structurallyValid at structurallyValid
          rw [← responseExact, storeExact] at structurallyValid
          exact structurallyValid.1.symm
        have countBound :
            store.kind.byteWidth <=
              max
                (witness.descriptor.command.expectedOperandBytes.getD 0)
                (witness.descriptor.command.expectedStoreKind.map
                  (·.byteWidth) |>.getD 0) := by
          rw [expectedStore]
          exact Nat.le_max_right _ _
        rw [witness.resultState, ← behaviorExact]
        simp [StageA.Relational.X87.singletonBehavior,
          RelationalBehavior.nextMachineState, applyX87MemoryEffect,
          storeExact]
        apply memoryAgreesOutside_writeX87BitsInside
        intro offset offsetBefore
        unfold nativeX87ReplayOperandFootprint
        rw [addressExact]
        exact ⟨offset, Nat.lt_of_lt_of_le offsetBefore countBound, rfl⟩

private theorem executeX87Singleton_esp
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    result.state.registers.esp = input.registers.esp := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have ran := witness.executed
  unfold StageA.Relational.X87.executeSingletonCommand at ran
  rw [witness.decoded] at ran
  simp [normalizeCodeTarget, singletonTarget] at ran
  split at ran
  · rcases ran with ⟨_, _, _, behaviorExact⟩
    have behaviorExact := Option.some.inj behaviorExact
    rw [witness.resultState, ← behaviorExact]
    cases registerExact :
        (input.x87Semantics.execute witness.descriptor.command
          witness.descriptor.waitMode input.x87Physical
          (StageA.Relational.X87.commandStepInput candidatePe
            record.span.start witness.descriptor input)).register <;>
    simp [StageA.Relational.X87.singletonBehavior,
      RelationalBehavior.nextMachineState, applyX87RegisterEffect,
      Registers.set, registerExact]
  · rcases ran with ⟨_, _, _, ran⟩
    cases addressExact :
        StageA.Relational.X87.commandDataAddress witness.descriptor input with
    | none => simp [addressExact] at ran
    | some address =>
        simp [addressExact] at ran
        rw [witness.resultState, ← ran]
        cases registerExact :
            (input.x87Semantics.execute witness.descriptor.command
              witness.descriptor.waitMode input.x87Physical
              (StageA.Relational.X87.commandStepInput candidatePe
                record.span.start witness.descriptor input)).register <;>
        simp [StageA.Relational.X87.singletonBehavior,
          RelationalBehavior.nextMachineState, applyX87RegisterEffect,
          Registers.set, registerExact]

/-- Expose the complete architectural register update selected by the shared
x87 response. -/
private theorem executeX87Singleton_registers
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    let witness :=
      executeX87Singleton_witness candidatePe record input result executed
    result.state.registers =
      applyX87RegisterEffect input.registers witness.effect.response := by
  dsimp only
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have ran := witness.executed
  unfold StageA.Relational.X87.executeSingletonCommand at ran
  rw [witness.decoded] at ran
  simp [normalizeCodeTarget, singletonTarget] at ran
  split at ran
  · rcases ran with ⟨_, _, _, behaviorExact⟩
    have behaviorExact := Option.some.inj behaviorExact
    rw [witness.resultState, ← behaviorExact]
    simp [StageA.Relational.X87.singletonBehavior,
      RelationalBehavior.nextMachineState]
    rw [witness.responseExecution]
  · rcases ran with ⟨_, _, _, ran⟩
    cases addressExact :
        StageA.Relational.X87.commandDataAddress witness.descriptor input with
    | none => simp [addressExact] at ran
    | some address =>
        simp [addressExact] at ran
        rw [witness.resultState, ← ran]
        simp [StageA.Relational.X87.singletonBehavior,
          RelationalBehavior.nextMachineState]
        rw [witness.responseExecution]

private theorem executeX87Singleton_register_other
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result)
    (register : Reg) (different : register ≠ .eax) :
    result.state.registers.get register = input.registers.get register := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  rw [executeX87Singleton_registers candidatePe record input result executed]
  unfold applyX87RegisterEffect
  cases registerEffect : witness.effect.response.register with
  | none => rfl
  | some effect =>
      cases effect
      cases register <;> simp_all [Registers.get] <;> rfl

/-- Expose the exact EFLAGS merge selected by the shared x87 response. -/
private theorem executeX87Singleton_eflags
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    let witness :=
      executeX87Singleton_witness candidatePe record input result executed
    result.state.eflags =
      applyX87FlagsEffect input.eflags witness.effect.response := by
  dsimp only
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have ran := witness.executed
  unfold StageA.Relational.X87.executeSingletonCommand at ran
  rw [witness.decoded] at ran
  simp [normalizeCodeTarget, singletonTarget] at ran
  split at ran
  · rcases ran with ⟨_, _, _, behaviorExact⟩
    have behaviorExact := Option.some.inj behaviorExact
    rw [witness.resultState, ← behaviorExact]
    simp [StageA.Relational.X87.singletonBehavior,
      RelationalBehavior.nextMachineState]
    rw [witness.responseExecution]
  · rcases ran with ⟨_, _, _, ran⟩
    cases addressExact :
        StageA.Relational.X87.commandDataAddress witness.descriptor input with
    | none => simp [addressExact] at ran
    | some address =>
        simp [addressExact] at ran
        rw [witness.resultState, ← ran]
        simp [StageA.Relational.X87.singletonBehavior,
          RelationalBehavior.nextMachineState]
        rw [witness.responseExecution]

private theorem executeX87Singleton_eflags_pushImage
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result)
    (inputExact :
      input.eflags &&& BitVec.ofNat 32 0xfffcffff = input.eflags) :
    result.state.eflags &&& BitVec.ofNat 32 0xfffcffff =
      result.state.eflags := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have structurallyValid :=
    input.x87Semantics.execute_structurallyValid
      input.x87Semantics.complies witness.descriptor.command
      witness.descriptor.waitMode input.x87Physical
      (StageA.Relational.X87.commandStepInput candidatePe
        record.span.start witness.descriptor input)
      (StageA.Relational.X87.decodeSingletonCommand_waitModeValid
        candidatePe record.span witness.descriptor witness.decoded)
      (StageA.Relational.X87.commandStepInput_valid candidatePe
        record.span.start witness.descriptor input)
  have maskExact :
      witness.effect.response.eflagsWriteMask =
        witness.descriptor.command.eflagsWriteMask := by
    rw [← witness.responseExecution] at structurallyValid
    exact structurallyValid.2.2.2.1
  rw [executeX87Singleton_eflags candidatePe record input result executed]
  exact applyX87FlagsEffect_pushImage input.eflags witness.descriptor.command
    witness.effect.response maskExact inputExact

private theorem executeX87Singleton_eflags_mergeNativeStatusMask
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    (input.eflags &&& BitVec.ofNat 32 0xfffff32a) |||
        (result.state.eflags &&& BitVec.ofNat 32 0x0cd5) =
      result.state.eflags := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have structurallyValid :=
    input.x87Semantics.execute_structurallyValid
      input.x87Semantics.complies witness.descriptor.command
      witness.descriptor.waitMode input.x87Physical
      (StageA.Relational.X87.commandStepInput candidatePe
        record.span.start witness.descriptor input)
      (StageA.Relational.X87.decodeSingletonCommand_waitModeValid
        candidatePe record.span witness.descriptor witness.decoded)
      (StageA.Relational.X87.commandStepInput_valid candidatePe
        record.span.start witness.descriptor input)
  have maskExact :
      witness.effect.response.eflagsWriteMask =
        witness.descriptor.command.eflagsWriteMask := by
    rw [← witness.responseExecution] at structurallyValid
    exact structurallyValid.2.2.2.1
  rw [executeX87Singleton_eflags candidatePe record input result executed]
  exact applyX87FlagsEffect_mergeNativeStatusMask input.eflags
    witness.descriptor.command witness.effect.response maskExact

private theorem executeX87Singleton_directionFlag
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    result.state.eflags.extractLsb' 10 1 =
      input.eflags.extractLsb' 10 1 := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have structurallyValid :=
    input.x87Semantics.execute_structurallyValid
      input.x87Semantics.complies witness.descriptor.command
      witness.descriptor.waitMode input.x87Physical
      (StageA.Relational.X87.commandStepInput candidatePe
        record.span.start witness.descriptor input)
      (StageA.Relational.X87.decodeSingletonCommand_waitModeValid
        candidatePe record.span witness.descriptor witness.decoded)
      (StageA.Relational.X87.commandStepInput_valid candidatePe
        record.span.start witness.descriptor input)
  have maskExact :
      witness.effect.response.eflagsWriteMask =
        witness.descriptor.command.eflagsWriteMask := by
    rw [← witness.responseExecution] at structurallyValid
    exact structurallyValid.2.2.2.1
  have maskBit :
      witness.descriptor.command.eflagsWriteMask.getLsbD 10 = false := by
    cases witness.descriptor.command <;>
      simp [StageA.X87.Command.eflagsWriteMask]
    split <;> simp [StageA.X87.Command.eflagsWriteMask]
  have maskElem :
      witness.descriptor.command.eflagsWriteMask[10] = false := by
    simpa only [← BitVec.getLsbD_eq_getElem] using maskBit
  rw [executeX87Singleton_eflags candidatePe record input result executed]
  apply BitVec.eq_of_getLsbD_eq_iff.mpr
  intro index bounded
  have indexZero : index = 0 := by omega
  subst index
  unfold applyX87FlagsEffect
  rw [maskExact]
  simp [maskElem]

private theorem executeX87Singleton_fsBase
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton candidatePe record input = some result) :
    result.state.fsBase = input.fsBase := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  rw [witness.resultState]
  simp [RelationalBehavior.nextMachineState, witness.effectBound]

private theorem nativeX87ReplayEffectiveAddress_eq_of_registers
    (addressing : Addressing) (left right : MachineState)
    (registers : left.registers = right.registers) :
    StageA.Relational.X87.effectiveAddress addressing left =
      StageA.Relational.X87.effectiveAddress addressing right := by
  have eaxExact := congrArg Registers.eax registers
  have ebxExact := congrArg Registers.ebx registers
  have ecxExact := congrArg Registers.ecx registers
  have edxExact := congrArg Registers.edx registers
  have esiExact := congrArg Registers.esi registers
  have ediExact := congrArg Registers.edi registers
  have ebpExact := congrArg Registers.ebp registers
  have espExact := congrArg Registers.esp registers
  rcases addressing with ⟨base, index, scaleShift, displacement⟩
  cases base <;> cases index
  all_goals try cases ‹Reg›
  all_goals try cases ‹Reg›
  all_goals cases scaleShift <;> cases displacement <;>
    simp [StageA.Relational.X87.effectiveAddress, Addressing.expression,
      initialSymbolic, Registers.get, Expr.addNormalized,
      StageA.Formal.Expr.eval, eaxExact, ebxExact, ecxExact, edxExact,
      esiExact, ediExact, ebpExact, espExact]

/-- Transport the exact singleton memory frame from its decoded execution
state to the admitted source-frame operand.  Keeping address-expression
reasoning behind this theorem prevents every later frame fact from reopening
the decoder and register-expression proof. -/
private theorem executeX87Singleton_memoryFrame_of_sourceOperand
    (candidatePe : PE32) (record : RawInstructionRecord)
    (input resultSource : MachineState) (result : StepResult)
    (sourceDescriptor : StageA.Relational.X87.DecodedCommand)
    (executed : executeX87Singleton candidatePe record input = some result)
    (decoded :
      StageA.Relational.X87.decodeSingletonCommand candidatePe record.span =
        some sourceDescriptor)
    (registers : input.registers = resultSource.registers) :
    MemoryAgreesOutside
      (nativeX87ReplayOperandFootprint sourceDescriptor resultSource)
      result.state.memory input.memory := by
  let witness :=
    executeX87Singleton_witness candidatePe record input result executed
  have descriptorExact : witness.descriptor = sourceDescriptor := by
    rw [← Option.some.injEq, ← witness.decoded]
    exact decoded
  have dataAddressExact :
      StageA.Relational.X87.commandDataAddress witness.descriptor input =
        StageA.Relational.X87.commandDataAddress
          sourceDescriptor resultSource := by
    rw [descriptorExact]
    unfold StageA.Relational.X87.commandDataAddress
    cases operand : sourceDescriptor.memoryOperand with
    | none => rfl
    | some addressing =>
        simp only [Option.map_some]
        exact congrArg some
          (nativeX87ReplayEffectiveAddress_eq_of_registers addressing input
            resultSource registers)
  have footprintExact :
      nativeX87ReplayOperandFootprint witness.descriptor input =
        nativeX87ReplayOperandFootprint sourceDescriptor resultSource := by
    rw [descriptorExact] at dataAddressExact
    unfold nativeX87ReplayOperandFootprint
    rw [descriptorExact, dataAddressExact]
  rw [← footprintExact]
  exact executeX87Singleton_memoryFrame candidatePe record input result executed

private theorem
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState captureInput)).memory
        (BitVec.ofNat 32
          ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
      source.frameAddress := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have entryRegisters : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have entryFrame :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded
  have candidateFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        candidateResult.state.memory entry.memory := by
    exact executeX87Singleton_memoryFrame_of_sourceOperand pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry source.candidateInput candidateResult
      source.commandInput.candidateDescriptor candidateExecuted
      source.commandInput.candidateDecoded entryRegisters
  have entryEsp : entry.registers.esp = logicalInput.registers.esp := by
    exact congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have captureInputMemory :
      captureInput.memory = candidateResult.state.memory := by
    simp [captureInput]
  have captureFrame :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memoryFrame table pe
      logicalInput captureInput captureInputEsp
  have pushedFrame :
      MemoryAgreesOutside
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState captureInput)).memory
        captureInput.memory := by
    simpa only [nativeX87ReplayFixedTemplateCaptureBeforeSaveState,
      nativeX87ReplayMovFromOperandState_memory] using captureFrame
  let activeRange :=
    nativeX87ReplayByteRange
      (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) 4
  have activeBounded := nativeX87ReplayActiveCellRvaBounded runtimeTarget
  have entryDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateEntryWriteFootprint source)
        activeRange :=
    candidateFootprintDisjointFromImage_byteRange pe _ _
      4 (nativeX87ReplayFixedTemplateEntryWriteDisjointImage source)
      imageBounded activeBounded
  have scratchDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        activeRange :=
    candidateFootprintDisjointFromImage_byteRange pe _ _
      4 source.replayScratchDisjointImage imageBounded activeBounded
  have operandDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        activeRange := by
    intro address operandMember activeMember
    exact source.operandDisjointRuntimeCells address operandMember
      (Or.inl activeMember)
  have activeAddressExact :
      BitVec.ofNat 32
          ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)) =
        BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva) := by
    exact wordOfNat_mod_wordSize _
  rw [activeAddressExact]
  calc
    Memory.read32
        (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState captureInput)).memory _ =
        Memory.read32 captureInput.memory _ :=
      memoryAgreesOutside_read32_of_disjoint pushedFrame scratchDisjoint
    _ = Memory.read32 candidateResult.state.memory _ := by
      rw [captureInputMemory]
    _ = Memory.read32 entry.memory _ :=
      memoryAgreesOutside_read32_of_disjoint candidateFrame operandDisjoint
    _ = Memory.read32 caller.memory _ :=
      memoryAgreesOutside_read32_of_disjoint entryFrame entryDisjoint
    _ = source.frameAddress := source.activeBefore

private theorem nativeX87ReplayFixedTemplateCaptureInput_readFrameCell
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (offset : Nat) (value : Word)
    (inside : offset + 4 <= 20)
    (separatePrivateEsp :
      offset + 4 <= nativeX87FramePrivateEspOffset ∨
        nativeX87FramePrivateEspOffset + 4 <= offset)
    (before :
      Memory.read32 caller.memory
          (source.frameAddress + BitVec.ofNat 32 offset) =
        value) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32 captureInput.memory
        (source.frameAddress + BitVec.ofNat 32 offset) =
      value := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have entryRegisters : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have entryFrame :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded
  have candidateFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        candidateResult.state.memory entry.memory := by
    exact executeX87Singleton_memoryFrame_of_sourceOperand pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry source.candidateInput candidateResult
      source.commandInput.candidateDescriptor candidateExecuted
      source.commandInput.candidateDecoded entryRegisters
  let targetRange :=
    nativeX87ReplayByteRange
      (source.frameAddress + BitVec.ofNat 32 offset) 4
  have targetInFrame :
      ∀ address, targetRange address ->
        nativeX87ReplayFrameFootprint source.frameAddress address := by
    intro address member
    rcases member with ⟨byte, byteBefore, rfl⟩
    exact ⟨offset + byte, by
      simp [nativeX87ReplayFrameBytes, nativeX87FrameOutputX87Offset,
        kernelX87FrameBytes]
      omega, by
      simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
  have entryDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateEntryWriteFootprint source)
        targetRange := by
    intro address entryMember targetMember
    rcases entryMember with preparation | scratch
    · rcases preparation with privateStack | privateEsp
      · exact source.privateStackDisjointFrame address privateStack
          (targetInFrame address targetMember)
      · exact
          (translatedByteRangesDisjoint source.frameAddress
            nativeX87FramePrivateEspOffset 4 offset 4
            (by decide) (by omega)
            (separatePrivateEsp.elim Or.inr Or.inl))
          address privateEsp targetMember
    · exact source.replayScratchDisjointFrame address scratch
        (targetInFrame address targetMember)
  have operandDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        targetRange := by
    intro address operandMember targetMember
    exact source.frameDisjointOperand address
      (targetInFrame address targetMember) operandMember
  have captureInputMemory :
      captureInput.memory = candidateResult.state.memory := by
    simp [captureInput]
  calc
    Memory.read32 captureInput.memory _ =
        Memory.read32 candidateResult.state.memory _ := by
      rw [captureInputMemory]
    _ = Memory.read32 entry.memory _ :=
      MemoryAgreesOutside.read32_of_disjoint candidateFrame operandDisjoint
    _ = Memory.read32 caller.memory _ :=
      MemoryAgreesOutside.read32_of_disjoint entryFrame entryDisjoint
    _ = value := before

private theorem nativeX87ReplayFixedTemplateCaptureInput_returnAddress
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32 captureInput.memory
        (nativeX87ReplayPrivateStackByte caller 16) =
      BitVec.ofNat 32 (pe.imageBase + table.continuationRva) := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have entryRegisters : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have candidateFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        candidateResult.state.memory entry.memory :=
    executeX87Singleton_memoryFrame_of_sourceOperand pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry source.candidateInput candidateResult
      source.commandInput.candidateDescriptor candidateExecuted
      source.commandInput.candidateDecoded entryRegisters
  have operandDisjointReturn :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        (nativeX87ReplayByteRange
          (nativeX87ReplayPrivateStackByte caller 16) 4) := by
    exact CandidateFootprintsDisjoint.mono
      source.privateStackDisjointOperand.symm
      (fun _ member => member)
      (by
        simpa [nativeX87ReplayPrivateStackByte] using
          nativeX87ReplayPrivateStackByteRange_subset caller 16 4 (by decide))
  calc
    Memory.read32 captureInput.memory
        (nativeX87ReplayPrivateStackByte caller 16) =
      Memory.read32 candidateResult.state.memory
        (nativeX87ReplayPrivateStackByte caller 16) := by
        rw [show captureInput.memory = candidateResult.state.memory by
          simp [captureInput]]
    _ = Memory.read32 entry.memory
        (nativeX87ReplayPrivateStackByte caller 16) :=
      MemoryAgreesOutside.read32_of_disjoint candidateFrame
        operandDisjointReturn
    _ = BitVec.ofNat 32 (pe.imageBase + table.continuationRva) :=
      nativeX87ReplayFixedTemplateInstructionEntryState_returnAddress
        runtimeTarget originalPe caller logicalInput source imageBounded

private theorem nativeX87ReplayFixedTemplateCaptureInput_privateStackPointer
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32 captureInput.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
      caller.registers.esp - BitVec.ofNat 32 20 := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have entryRegisters : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have candidateFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        candidateResult.state.memory entry.memory :=
    executeX87Singleton_memoryFrame_of_sourceOperand pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry source.candidateInput candidateResult
      source.commandInput.candidateDescriptor candidateExecuted
      source.commandInput.candidateDecoded entryRegisters
  have operandDisjointPrivateEsp :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4) :=
    CandidateFootprintsDisjoint.mono source.frameDisjointOperand.symm
      (fun _ member => member)
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FramePrivateEspOffset 4 (by decide))
  calc
    Memory.read32 captureInput.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
      Memory.read32 candidateResult.state.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) := by
        rw [show captureInput.memory = candidateResult.state.memory by
          simp [captureInput]]
    _ = Memory.read32 entry.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) :=
      MemoryAgreesOutside.read32_of_disjoint candidateFrame
        operandDisjointPrivateEsp
    _ = caller.registers.esp - BitVec.ofNat 32 20 :=
      nativeX87ReplayFixedTemplateInstructionEntryState_privateStackPointer
        runtimeTarget originalPe caller logicalInput source imageBounded

private theorem nativeX87ReplayFixedTemplateCaptureSaved_readFrameCell
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (offset : Nat) (value : Word)
    (inside : offset + 4 <= 20)
    (separatePrivateEsp :
      offset + 4 <= nativeX87FramePrivateEspOffset ∨
        nativeX87FramePrivateEspOffset + 4 <= offset)
    (before :
      Memory.read32 caller.memory
          (source.frameAddress + BitVec.ofNat 32 offset) =
        value) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureSavedState table pe
          source.frameAddress captureInput).memory
        (source.frameAddress + BitVec.ofNat 32 offset) =
      value := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have captureInputRead :=
    nativeX87ReplayFixedTemplateCaptureInput_readFrameCell runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted offset value inside separatePrivateEsp before
  have entryEsp :
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).registers.esp =
      logicalInput.registers.esp := by
    exact congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller)
      candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have scratchFrame :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memoryFrame table pe
      logicalInput captureInput captureInputEsp
  have saveFrame :=
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryFrame table pe
      source.frameAddress captureInput
  let targetRange :=
    nativeX87ReplayByteRange
      (source.frameAddress + BitVec.ofNat 32 offset) 4
  have targetInFrame :
      ∀ address, targetRange address ->
        nativeX87ReplayFrameFootprint source.frameAddress address := by
    intro address member
    rcases member with ⟨byte, byteBefore, rfl⟩
    exact ⟨offset + byte, by
      simp [nativeX87ReplayFrameBytes, nativeX87FrameOutputX87Offset,
        kernelX87FrameBytes]
      omega, by
      simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
  have scratchDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        targetRange := by
    intro address scratchMember targetMember
    exact source.replayScratchDisjointFrame address scratchMember
      (targetInFrame address targetMember)
  have saveDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          kernelX87FrameBytes)
        targetRange :=
    translatedByteRangesDisjoint source.frameAddress
      nativeX87FrameOutputX87Offset kernelX87FrameBytes offset 4
      (by decide) (by omega) (Or.inr (by
        simpa [nativeX87FrameOutputX87Offset] using
          Nat.le_trans inside (by decide : 20 <= 128)))
  calc
    Memory.read32 saved.memory _ =
        Memory.read32 beforeSave.memory _ :=
      MemoryAgreesOutside.read32_of_disjoint saveFrame saveDisjoint
    _ = Memory.read32 captureInput.memory _ :=
      MemoryAgreesOutside.read32_of_disjoint scratchFrame scratchDisjoint
    _ = value := by simpa [captureInput] using captureInputRead

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryOnRepresentation
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    ∀ address, Engine.CandidateAddressObserved source.rep address ->
      saved.memory address = caller.memory address := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have entryRegisters : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have entryFrame :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded
  have candidateFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        candidateResult.state.memory entry.memory :=
    executeX87Singleton_memoryFrame_of_sourceOperand pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry source.candidateInput candidateResult
      source.commandInput.candidateDescriptor candidateExecuted
      source.commandInput.candidateDecoded entryRegisters
  have entryEsp : entry.registers.esp = logicalInput.registers.esp := by
    exact congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have scratchFrame :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memoryFrame table pe
      logicalInput captureInput captureInputEsp
  have saveFrame :=
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryFrame table pe
      source.frameAddress captureInput
  intro address observed
  calc
    saved.memory address = beforeSave.memory address :=
      saveFrame address (fun member =>
        source.stackDisjoint address
          (nativeX87ReplayFrameByteRange_subset source.frameAddress
            nativeX87FrameOutputX87Offset kernelX87FrameBytes (by decide)
            address member)
          observed)
    _ = captureInput.memory address :=
      scratchFrame address (fun member =>
        source.replayScratchDisjointRepresentation address member observed)
    _ = candidateResult.state.memory address := by
      simp [captureInput]
    _ = entry.memory address :=
      candidateFrame address (fun member =>
        source.operandDisjointRepresentation address member observed)
    _ = caller.memory address :=
      entryFrame address (fun member =>
        match member with
        | Or.inl preparation =>
            nativeX87ReplayFixedTemplateEntryPreparationDisjointRepresentation
              source address preparation observed
        | Or.inr scratch =>
            source.replayScratchDisjointRepresentation address scratch observed)

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedState_savedEax
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    Memory.read32 saved.memory saved.registers.esp =
      candidateResult.state.registers.eax := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have entryEsp : entry.registers.esp = logicalInput.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have beforeSaveEsp :
      beforeSave.registers.esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
    exact
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState_esp table pe
        captureInput).trans (congrArg
          (fun esp => esp -
            BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes)
          captureInputEsp)
  have pushedEsp :
      (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState captureInput)).registers.esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
    rw [nativeX87ReplayPushRegState_registers,
      nativeX87ReplayPushFlagsState_registers, captureInputEsp]
    simpa only [nativeX87ReplayLogicalScratchBytes] using
      word_sub_four_twice_eq_sub_eight logicalInput.registers.esp
  have beforeSaveTop :
      Memory.read32 beforeSave.memory beforeSave.registers.esp =
        captureInput.registers.eax := by
    rw [show beforeSave.memory =
        (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState captureInput)).memory by
      simpa [beforeSave] using
        nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memory table pe
          captureInput]
    rw [beforeSaveEsp, ← pushedEsp]
    exact nativeX87ReplayCapturePushes_savedEax captureInput
  have savedEsp : saved.registers.esp = beforeSave.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayFixedTemplateCaptureSavedState_registers table pe
        source.frameAddress captureInput)
  have saveFrame :=
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryFrame table pe
      source.frameAddress captureInput
  have saveDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          kernelX87FrameBytes)
        (nativeX87ReplayByteRange beforeSave.registers.esp 4) := by
    apply CandidateFootprintsDisjoint.mono
      source.replayScratchDisjointFrame.symm
    · exact nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes (by decide)
    · intro address member
      rw [beforeSaveEsp] at member
      rcases member with ⟨byte, byteBefore, rfl⟩
      exact ⟨byte, by
        simpa [nativeX87ReplayLogicalScratchBytes] using
          Nat.lt_of_lt_of_le byteBefore (by decide : 4 <= 8), rfl⟩
  calc
    Memory.read32 saved.memory saved.registers.esp =
        Memory.read32 saved.memory beforeSave.registers.esp := by
      rw [savedEsp]
    _ = Memory.read32 beforeSave.memory beforeSave.registers.esp :=
      MemoryAgreesOutside.read32_of_disjoint saveFrame saveDisjoint
    _ = captureInput.registers.eax := beforeSaveTop
    _ = candidateResult.state.registers.eax := by
      simp [captureInput]

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedState_savedFlags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    Memory.read32 saved.memory
        (saved.registers.esp + BitVec.ofNat 32 4) =
      candidateResult.state.eflags := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have entryEsp : entry.registers.esp = logicalInput.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have beforeSaveEsp :
      beforeSave.registers.esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
    exact
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState_esp table pe
        captureInput).trans (congrArg
          (fun esp => esp -
            BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes)
          captureInputEsp)
  have flagsSavedEsp :
      (nativeX87ReplayPushFlagsState captureInput).registers.esp =
        beforeSave.registers.esp + BitVec.ofNat 32 4 := by
    rw [nativeX87ReplayPushFlagsState_registers, captureInputEsp,
      beforeSaveEsp]
    simpa only [nativeX87ReplayLogicalScratchBytes] using
      word_sub_four_eq_sub_eight_add_four logicalInput.registers.esp
  have candidatePushImage :
      candidateResult.state.eflags &&&
          BitVec.ofNat 32 0xfffcffff =
        candidateResult.state.eflags := by
    apply executeX87Singleton_eflags_pushImage pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry candidateResult candidateExecuted
    rw [nativeX87ReplayFixedTemplateInstructionEntryState_eflags_exact
      runtimeTarget originalPe caller logicalInput source imageBounded]
    exact cpl3PopFlagsSourceFrameChecked_push_image caller logicalInput.eflags
      source.popFlagsCpl3
  have captureInputEflags :
      captureInput.eflags = candidateResult.state.eflags := by
    simp [captureInput]
  have beforeSaveFlags :
      Memory.read32 beforeSave.memory
          (beforeSave.registers.esp + BitVec.ofNat 32 4) =
        candidateResult.state.eflags := by
    rw [show beforeSave.memory =
        (nativeX87ReplayPushRegState .eax
          (nativeX87ReplayPushFlagsState captureInput)).memory by
      simpa [beforeSave] using
        nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memory table pe
          captureInput]
    rw [← flagsSavedEsp]
    calc
      _ = (Expr.bitAnd initialSymbolic.eflagsExpression
          (.constant 0xfffcffff)).eval captureInput :=
        nativeX87ReplayCapturePushes_savedFlags captureInput
      _ = captureInput.eflags &&& BitVec.ofNat 32 0xfffcffff := by
        simp [StageA.Formal.Expr.eval, initialSymbolicEflagsExpression_eval]
      _ = candidateResult.state.eflags := by
        rw [captureInputEflags, candidatePushImage]
  have savedEsp : saved.registers.esp = beforeSave.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayFixedTemplateCaptureSavedState_registers table pe
        source.frameAddress captureInput)
  have saveFrame :=
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryFrame table pe
      source.frameAddress captureInput
  have saveDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          kernelX87FrameBytes)
        (nativeX87ReplayByteRange
          (beforeSave.registers.esp + BitVec.ofNat 32 4) 4) := by
    apply CandidateFootprintsDisjoint.mono
      source.replayScratchDisjointFrame.symm
    · exact nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes (by decide)
    · intro address member
      rw [beforeSaveEsp] at member
      rcases member with ⟨byte, byteBefore, rfl⟩
      exact ⟨4 + byte, by
        simpa [nativeX87ReplayLogicalScratchBytes] using
          Nat.add_lt_add_left byteBefore 4, by
        simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
  calc
    Memory.read32 saved.memory
        (saved.registers.esp + BitVec.ofNat 32 4) =
      Memory.read32 saved.memory
        (beforeSave.registers.esp + BitVec.ofNat 32 4) := by rw [savedEsp]
    _ = Memory.read32 beforeSave.memory
        (beforeSave.registers.esp + BitVec.ofNat 32 4) :=
      MemoryAgreesOutside.read32_of_disjoint saveFrame saveDisjoint
    _ = candidateResult.state.eflags := beforeSaveFlags

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedState_readPresentFieldAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (field : Engine.EngineField) (offset : Nat)
    (canonical : nativeX87ReplayEngineFieldOffset? field = some offset)
    (entry : Engine.EngineFieldLayout)
    (member : entry ∈ source.rep.layout.fields)
    (fieldExact : entry.field = field) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    some (Engine.readBytes saved.memory
      (source.outputAddress + BitVec.ofNat 32 offset) field.byteWidth) =
        source.rep.fieldBytes logicalInput
          runtimeTarget.target.descriptor.replay.rvaStart field := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  have entryOffset := List.all_eq_true.mp layout.1.2 entry member
  simp only [fieldExact, canonical, beq_iff_eq, Option.some.injEq] at entryOffset
  have memoryOnRepresentation :=
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryOnRepresentation
      runtimeTarget static originalPe caller logicalInput source imageBounded
      candidateResult candidateExecuted
  have bytesExact :
      Engine.readBytes saved.memory
          (source.outputAddress + BitVec.ofNat 32 offset) field.byteWidth =
        Engine.readBytes caller.memory
          (source.outputAddress + BitVec.ofNat 32 offset) field.byteWidth := by
    unfold Engine.readBytes
    apply List.map_congr_left
    intro byte byteMember
    apply memoryOnRepresentation
    apply Or.inl
    refine ⟨entry, member, byte, ?_, ?_⟩
    · simpa [fieldExact] using List.mem_range.mp byteMember
    · simp [Engine.EngineFieldLayout.address, source.engineBase, entryOffset,
        BitVec.add_assoc]
  calc
    some (Engine.readBytes saved.memory _ _) =
        some (Engine.readBytes caller.memory _ _) := congrArg some bytesExact
    _ = source.rep.fieldBytes logicalInput
          runtimeTarget.target.descriptor.replay.rvaStart field := by
      simpa [fieldExact] using
        source.readPresentFieldAtOffset entry offset member
          (by simpa [fieldExact] using canonical)

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedState_readEflags
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    Memory.read32 saved.memory
        (source.outputAddress + BitVec.ofNat 32 240) =
      logicalInput.eflags := by
  dsimp only
  rcases source.engineRelated.repValid.1 with
    ⟨_stateSizePositive, _stateSizeBound, _fieldsNodup, _fieldsValid,
      _fieldsDisjoint, fieldsComplete⟩
  have required : Engine.EngineField.eflags ∈
      source.rep.layout.requiredFields := by
    simp [Engine.EngineLayout.requiredFields]
  rcases List.mem_map.mp (fieldsComplete .eflags required) with
    ⟨entry, member, fieldExact⟩
  have represented :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readPresentFieldAtOffset
      runtimeTarget static originalPe caller logicalInput source imageBounded
      candidateResult candidateExecuted .eflags 240 (by decide) entry member
      fieldExact
  have encoded :
      Engine.readBytes
          (nativeX87ReplayFixedTemplateCaptureSavedState table pe
            source.frameAddress
            (nativeX87ReplayNopState
              (nativeX87ReplayFixedTemplateInstructionRegionSize -
                static.candidateDescriptor.size)
              candidateResult.state)).memory
          (source.outputAddress + BitVec.ofNat 32 240) 4 =
        Engine.encodeLittleEndian 4 logicalInput.eflags.toNat := by
    simpa [Engine.EngineRep.fieldBytes, Engine.EngineField.byteWidth] using
      Option.some.inj represented
  exact Memory.read32_eq_of_engineBytes4 _ _ _ encoded

private theorem
    nativeX87ReplayFixedTemplateCaptureSavedState_readFlagAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (bit offset : Nat)
    (required : Engine.EngineField.flag bit ∈
      nativeX87ReplayRequiredFlagFields)
    (canonical :
      nativeX87ReplayEngineFieldOffset? (.flag bit) = some offset) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    Memory.read32 saved.memory
        (source.outputAddress + BitVec.ofNat 32 offset) =
      BitVec.ofNat 32 (logicalInput.eflags.extractLsb' bit 1).toNat := by
  dsimp only
  rcases source.flagFieldPresent bit required with
    ⟨entry, member, fieldExact⟩
  have represented :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readPresentFieldAtOffset
      runtimeTarget static originalPe caller logicalInput source imageBounded
      candidateResult candidateExecuted (.flag bit) offset canonical entry
      member fieldExact
  have encoded :
      Engine.readBytes
          (nativeX87ReplayFixedTemplateCaptureSavedState table pe
            source.frameAddress
            (nativeX87ReplayNopState
              (nativeX87ReplayFixedTemplateInstructionRegionSize -
                static.candidateDescriptor.size)
              candidateResult.state)).memory
          (source.outputAddress + BitVec.ofNat 32 offset) 4 =
        Engine.encodeLittleEndian 4
          (logicalInput.eflags.extractLsb' bit 1).toNat := by
    simpa [Engine.EngineRep.fieldBytes, Engine.EngineField.byteWidth] using
      Option.some.inj represented
  have valueBound :
      (logicalInput.eflags.extractLsb' bit 1).toNat < 2 ^ 32 := by
    have oneBitBound := (logicalInput.eflags.extractLsb' bit 1).isLt
    omega
  have valueToNat :
      (BitVec.ofNat 32
        (logicalInput.eflags.extractLsb' bit 1).toNat).toNat =
          (logicalInput.eflags.extractLsb' bit 1).toNat := by
    rw [BitVec.toNat_ofNat]
    exact Nat.mod_eq_of_lt valueBound
  apply Memory.read32_eq_of_engineBytes4
  rw [valueToNat]
  exact encoded

private theorem nativeX87ReplayFixedTemplateCaptureSaved_eax
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    saved.registers.get .eax = source.frameAddress := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have active :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have beforeSaveEax :
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
        captureInput).registers.eax = source.frameAddress :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax table pe
      source.frameAddress captureInput active
  rw [show saved.registers =
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
        captureInput).registers by
    simpa [saved] using
      nativeX87ReplayFixedTemplateCaptureSavedState_registers table pe
        source.frameAddress captureInput]
  simpa [Registers.get] using beforeSaveEax

private theorem nativeX87ReplayFixedTemplateCaptureSaved_esp
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    saved.registers.get .esp =
      logicalInput.registers.esp -
        BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have entryEsp : entry.registers.esp = logicalInput.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have beforeSaveEsp :
      beforeSave.registers.esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes :=
    (nativeX87ReplayFixedTemplateCaptureBeforeSaveState_esp table pe
      captureInput).trans (congrArg
        (fun esp => esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes)
        captureInputEsp)
  rw [show saved.registers = beforeSave.registers by
    simpa [saved, beforeSave] using
      nativeX87ReplayFixedTemplateCaptureSavedState_registers table pe
        source.frameAddress captureInput]
  simpa [Registers.get] using beforeSaveEsp

private theorem nativeX87ReplayFixedTemplateCaptureSaved_outputLoaded
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    (nativeX87ReplayFixedTemplateCaptureOutputLoadedState
      saved).registers.get .edx = source.outputAddress := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have active :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have beforeSaveEax :
      (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
        captureInput).registers.eax = source.frameAddress :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax table pe
      source.frameAddress captureInput active
  have savedEax : saved.registers.eax = source.frameAddress := by
    dsimp [saved]
    rw [nativeX87ReplayFixedTemplateCaptureSavedState_registers]
    exact beforeSaveEax
  have outputPointer :
      Memory.read32 saved.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameOutputOffset) =
        source.outputAddress := by
    exact nativeX87ReplayFixedTemplateCaptureSaved_readFrameCell runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted nativeX87FrameOutputOffset source.outputAddress
      (by decide) (Or.inl (by decide)) source.outputPointer
  exact nativeX87ReplayFixedTemplateCaptureOutputLoadedState_edx saved
    source.frameAddress source.outputAddress savedEax outputPointer

private theorem
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState_ecx_exact
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    (nativeX87ReplayFixedTemplateCaptureMergedFlagsState undefinedSlot
      saved).registers.get .ecx = candidateResult.state.eflags := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let savedFlags :=
    nativeX87ReplayFixedTemplateCaptureSavedFlagsState saved
  let inputLoaded :=
    nativeX87ReplayFixedTemplateCaptureInputLoadedState saved
  let inputFlags :=
    nativeX87ReplayFixedTemplateCaptureInputFlagsState saved
  let ofWritten :=
    nativeX87ReplayFixedTemplateCaptureOfWrittenState saved
  have savedFlagsRead :
      Memory.read32 saved.memory
          (saved.registers.esp + BitVec.ofNat 32 4) =
        candidateResult.state.eflags := by
    simpa only [saved, captureInput] using
      nativeX87ReplayFixedTemplateCaptureSavedState_savedFlags runtimeTarget
        static originalPe caller logicalInput source imageBounded
        candidateResult candidateExecuted
  have outputLoaded :=
    nativeX87ReplayFixedTemplateCaptureSaved_outputLoaded runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have ofFrame :
      MemoryAgreesOutside
        (nativeX87ReplayFlagWriteFootprint source.outputAddress)
        ofWritten.memory saved.memory := by
    simpa only [ofWritten] using
      nativeX87ReplayFixedTemplateCaptureOfWrittenState_memoryFrame saved
        source.outputAddress outputLoaded
  have ofEsp : ofWritten.registers.get .esp = saved.registers.get .esp := by
    simpa only [ofWritten] using
      nativeX87ReplayFixedTemplateCaptureOfWrittenState_register_other
        saved .esp (by decide) (by decide)
  have savedEsp :
      saved.registers.get .esp =
        logicalInput.registers.esp -
          BitVec.ofNat 32 nativeX87ReplayLogicalScratchBytes :=
    nativeX87ReplayFixedTemplateCaptureSaved_esp runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have flagsCellDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFlagWriteFootprint source.outputAddress)
        (nativeX87ReplayByteRange
          (ofWritten.registers.get .esp + BitVec.ofNat 32 4) 4) := by
    rw [ofEsp, savedEsp]
    intro address writeMember scratchMember
    apply source.replayScratchDisjointRepresentation address
    · rcases scratchMember with ⟨byte, byteBefore, rfl⟩
      exact ⟨4 + byte, by
        simpa [nativeX87ReplayLogicalScratchBytes] using
          Nat.add_lt_add_left byteBefore 4, by
        simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩
    · exact nativeX87ReplayFlagWriteFootprint_observed source address writeMember
  have ofSavedFlagsRead :
      Memory.read32 ofWritten.memory
          (ofWritten.registers.get .esp + BitVec.ofNat 32 4) =
        candidateResult.state.eflags := by
    calc
      _ = Memory.read32 saved.memory
          (ofWritten.registers.get .esp + BitVec.ofNat 32 4) :=
        MemoryAgreesOutside.read32_of_disjoint ofFrame flagsCellDisjoint
      _ = Memory.read32 saved.memory
          (saved.registers.get .esp + BitVec.ofNat 32 4) := by rw [ofEsp]
      _ = candidateResult.state.eflags := savedFlagsRead
  have savedFlagsEbx :
      savedFlags.registers.get .ebx = candidateResult.state.eflags := by
    simpa only [savedFlags] using
      nativeX87ReplayFixedTemplateCaptureSavedFlagsState_ebx saved
        candidateResult.state.eflags ofSavedFlagsRead
  have savedEax : saved.registers.get .eax = source.frameAddress := by
    exact nativeX87ReplayFixedTemplateCaptureSaved_eax runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have ofEax : ofWritten.registers.get .eax = source.frameAddress := by
    have preserved : ofWritten.registers.get .eax =
        saved.registers.get .eax := by
      simpa only [ofWritten] using
        nativeX87ReplayFixedTemplateCaptureOfWrittenState_register_other
          saved .eax (by decide) (by decide)
    exact preserved.trans savedEax
  have savedFlagsEax :
      savedFlags.registers.get .eax = source.frameAddress := by
    simpa only [savedFlags] using
      nativeX87ReplayFixedTemplateCaptureSavedFlagsState_register_other saved
        .eax source.frameAddress (by decide) ofEax
  have inputPointer :
      Memory.read32 saved.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameInputOffset) =
        source.inputAddress :=
    nativeX87ReplayFixedTemplateCaptureSaved_readFrameCell runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted nativeX87FrameInputOffset source.inputAddress
      (by decide) (Or.inl (by decide)) source.inputPointer
  have frameInputDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFlagWriteFootprint source.outputAddress)
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameInputOffset) 4) := by
    intro address writeMember frameMember
    exact source.stackDisjoint address
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameInputOffset 4 (by decide) address frameMember)
      (nativeX87ReplayFlagWriteFootprint_observed source address writeMember)
  have ofInputPointer :
      Memory.read32 ofWritten.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameInputOffset) =
        source.inputAddress :=
    (MemoryAgreesOutside.read32_of_disjoint ofFrame frameInputDisjoint).trans
      inputPointer
  have savedFlagsMemory : savedFlags.memory = ofWritten.memory := by
    dsimp [savedFlags,
      nativeX87ReplayFixedTemplateCaptureSavedFlagsState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have savedFlagsInputPointer :
      Memory.read32 savedFlags.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameInputOffset) =
        source.inputAddress := by
    rw [savedFlagsMemory]
    exact ofInputPointer
  have inputLoadedEcx :
      inputLoaded.registers.get .ecx = source.inputAddress := by
    simpa only [inputLoaded] using
      nativeX87ReplayFixedTemplateCaptureInputLoadedState_ecx saved
        source.frameAddress source.inputAddress savedFlagsEax
        savedFlagsInputPointer
  have savedInputEflags :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readEflags runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have ofInputEflags :
      Memory.read32 ofWritten.memory
          (source.outputAddress + BitVec.ofNat 32 240) =
        logicalInput.eflags :=
    (MemoryAgreesOutside.read32_of_disjoint ofFrame
      (nativeX87ReplayFlagWriteFootprint_disjointEflags
        source.outputAddress)).trans savedInputEflags
  have inputLoadedMemory : inputLoaded.memory = savedFlags.memory := by
    dsimp [inputLoaded,
      nativeX87ReplayFixedTemplateCaptureInputLoadedState]
    exact nativeX87ReplayMovFromOperandState_memory _ _ _
  have inputLoadedEflags :
      Memory.read32 inputLoaded.memory
          (source.outputAddress + BitVec.ofNat 32 240) =
        logicalInput.eflags := by
    rw [inputLoadedMemory, savedFlagsMemory]
    exact ofInputEflags
  have inputFlagsEcx :
      inputFlags.registers.get .ecx = logicalInput.eflags := by
    apply nativeX87ReplayFixedTemplateCaptureInputFlagsState_ecx saved
      source.inputAddress logicalInput.eflags
    · exact inputLoadedEcx
    · rw [source.inputOutputAlias]
      exact inputLoadedEflags
  have inputFlagsEbx :
      inputFlags.registers.get .ebx = candidateResult.state.eflags := by
    simpa only [inputFlags] using
      nativeX87ReplayFixedTemplateCaptureInputFlagsState_ebx saved
        candidateResult.state.eflags savedFlagsEbx
  have mergedExact :
      (logicalInput.eflags &&& BitVec.ofNat 32 0xfffff32a) |||
          (candidateResult.state.eflags &&& BitVec.ofNat 32 0x0cd5) =
        candidateResult.state.eflags := by
    have exact :=
      executeX87Singleton_eflags_mergeNativeStatusMask pe
        (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
          runtimeTarget.addressMap.candidateInstructionRva)
        entry candidateResult candidateExecuted
    rw [nativeX87ReplayFixedTemplateInstructionEntryState_eflags_exact
      runtimeTarget originalPe caller logicalInput source imageBounded] at exact
    exact exact
  simpa only [nativeX87ReplayFixedTemplateCaptureMergedFlagsState,
    nativeX87ReplayFixedTemplateCaptureResultFlagsState,
    nativeX87ReplayFixedTemplateCapturePreservedFlagsState, inputFlags] using
    nativeX87ReplayMergedFlagsState_ecx undefinedSlot inputFlags
      logicalInput.eflags candidateResult.state.eflags inputFlagsEcx
      inputFlagsEbx mergedExact

private theorem
    nativeX87ReplayFixedTemplateCaptureFinalState_outputProjection
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    NativeX87ReplayOutputProjection
      (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput).memory
      source.outputAddress candidateResult.state.registers
      candidateResult.state.eflags := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let output :=
    nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
      source.frameAddress saved
  let final :=
    nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
      source.frameAddress captureInput
  have outputLoaded :=
    nativeX87ReplayFixedTemplateCaptureSaved_outputLoaded runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have savedEax :
      Memory.read32 saved.memory saved.registers.esp =
        candidateResult.state.registers.eax := by
    simpa only [saved, Registers.get] using
      nativeX87ReplayFixedTemplateCaptureSavedState_savedEax runtimeTarget
        static originalPe caller logicalInput source imageBounded
        candidateResult candidateExecuted
  have savedEflags : saved.eflags = candidateResult.state.eflags := by
    dsimp [saved, nativeX87ReplayFixedTemplateCaptureSavedState]
    rw [nativeX87ReplayFnSaveState_eflags,
      nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eflags]
    simp [captureInput]
  have carryBefore :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readFlagAtOffset runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted 0 32 (by decide) (by decide)
  have parityBefore :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readFlagAtOffset runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted 2 48 (by decide) (by decide)
  have zeroBefore :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readFlagAtOffset runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted 6 36 (by decide) (by decide)
  have signBefore :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readFlagAtOffset runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted 7 40 (by decide) (by decide)
  have overflowBefore :=
    nativeX87ReplayFixedTemplateCaptureSavedState_readFlagAtOffset runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted 11 44 (by decide) (by decide)
  have merged :=
    nativeX87ReplayFixedTemplateCaptureMergedFlagsState_ecx_exact runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have outputProjection :
      NativeX87ReplayOutputProjection output.memory source.outputAddress
        candidateResult.state.registers candidateResult.state.eflags := by
    simpa only [output, saved] using
      nativeX87ReplayFixedTemplateOutputWrittenState_projection undefinedSlot
        source.frameAddress source.outputAddress saved
        candidateResult.state.registers logicalInput.eflags
        candidateResult.state.eflags outputLoaded savedEax savedEflags
        carryBefore parityBefore zeroBefore signBefore overflowBefore merged
  have savedRegisterEax : saved.registers.get .eax = source.frameAddress :=
    nativeX87ReplayFixedTemplateCaptureSaved_eax runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have outputEax : output.registers.get .eax = source.frameAddress :=
    (nativeX87ReplayFixedTemplateOutputWrittenState_eax undefinedSlot
      source.frameAddress saved).trans savedRegisterEax
  have finalMemory :
      final.memory =
        output.memory.write32
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameStatusOffset)
          (BitVec.ofNat 32 0) := by
    simpa only [final, output,
      nativeX87ReplayFixedTemplateCaptureFinalState] using
      nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory
        source.frameAddress output outputEax
  have preserved :
      ∀ offset ∈ nativeX87ReplayOutputWriteOffsets,
        Memory.read32 final.memory
            (source.outputAddress + BitVec.ofNat 32 offset) =
          Memory.read32 output.memory
            (source.outputAddress + BitVec.ofNat 32 offset) := by
    intro offset included
    rw [finalMemory]
    apply MemoryAgreesOutside.read32_of_disjoint
      (MemoryAgreesOutside.write32ByteRange output.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FrameStatusOffset)
        (BitVec.ofNat 32 0))
    intro address statusMember outputMember
    exact source.stackDisjoint address
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameStatusOffset 4 (by decide) address statusMember)
      (nativeX87ReplayOutputWriteFootprint_observed source address
        ⟨offset, included, outputMember⟩)
  exact {
    eax := by
      have preservedEax :
          Memory.read32 final.memory source.outputAddress =
            Memory.read32 output.memory source.outputAddress := by
        simpa using preserved 0 (by decide)
      exact preservedEax.trans outputProjection.eax
    carry := (preserved 32 (by decide)).trans outputProjection.carry
    parity := (preserved 48 (by decide)).trans outputProjection.parity
    zero := (preserved 36 (by decide)).trans outputProjection.zero
    sign := (preserved 40 (by decide)).trans outputProjection.sign
    overflow := (preserved 44 (by decide)).trans outputProjection.overflow
    eflags := (preserved 240 (by decide)).trans outputProjection.eflags
  }

private theorem nativeX87ReplayOutputWriteFootprint_disjointOffset
    (outputAddress : Word) (offset : Nat)
    (offsetBounded : offset + 4 <= 2 ^ 32)
    (separated :
      ∀ writeOffset ∈ nativeX87ReplayOutputWriteOffsets,
        writeOffset + 4 <= offset ∨ offset + 4 <= writeOffset) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayOutputWriteFootprint outputAddress)
      (nativeX87ReplayByteRange
        (outputAddress + BitVec.ofNat 32 offset) 4) := by
  intro address writeMember readMember
  rcases writeMember with ⟨writeOffset, included, byteMember⟩
  have writeBounded : writeOffset + 4 <= 2 ^ 32 := by
    simp only [nativeX87ReplayOutputWriteOffsets, List.mem_cons,
      List.mem_singleton, List.not_mem_nil, or_false] at included
    rcases included with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> decide
  exact
    (translatedByteRangesDisjoint outputAddress writeOffset 4 offset 4
      writeBounded
      offsetBounded
      (separated writeOffset included))
      address byteMember readMember

private theorem
    nativeX87ReplayFixedTemplateCaptureFinalState_postSaveMemoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let saved :=
      nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
        captureInput
    MemoryAgreesOutside
      (footprintUnion
        (nativeX87ReplayOutputWriteFootprint source.outputAddress)
        (nativeX87ReplayByteRange
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) 4))
      (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput).memory
      saved.memory := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let output :=
    nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
      source.frameAddress saved
  have outputLoaded :=
    nativeX87ReplayFixedTemplateCaptureSaved_outputLoaded runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have outputFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint source.outputAddress)
        output.memory saved.memory := by
    simpa only [output, saved] using
      nativeX87ReplayFixedTemplateOutputWrittenState_memoryFrame undefinedSlot
        source.frameAddress source.outputAddress saved outputLoaded
  have savedEax : saved.registers.get .eax = source.frameAddress :=
    nativeX87ReplayFixedTemplateCaptureSaved_eax runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have outputEax : output.registers.get .eax = source.frameAddress :=
    (nativeX87ReplayFixedTemplateOutputWrittenState_eax undefinedSlot
      source.frameAddress saved).trans savedEax
  have returnFrame :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) 4)
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        output.memory := by
    rw [nativeX87ReplayFixedTemplateCaptureFinalState,
      nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory
        source.frameAddress output outputEax]
    exact MemoryAgreesOutside.write32ByteRange output.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset)
      (BitVec.ofNat 32 0)
  exact MemoryAgreesOutside.compose outputFrame returnFrame

private theorem
    nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (field : Engine.EngineField) (offset : Nat)
    (canonical : nativeX87ReplayEngineFieldOffset? field = some offset)
    (width : field.byteWidth = 4)
    (entry : Engine.EngineFieldLayout)
    (member : entry ∈ source.rep.layout.fields)
    (fieldExact : entry.field = field)
    (outputDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOutputWriteFootprint source.outputAddress)
        (nativeX87ReplayByteRange
          (source.outputAddress + BitVec.ofNat 32 offset) 4)) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    some (Engine.readBytes
      (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput).memory
      (source.outputAddress + BitVec.ofNat 32 offset) 4) =
        source.rep.fieldBytes logicalInput
          runtimeTarget.target.descriptor.replay.rvaStart field := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  have frame :=
    nativeX87ReplayFixedTemplateCaptureFinalState_postSaveMemoryFrame
      runtimeTarget static originalPe caller logicalInput source imageBounded
      undefinedSlot candidateResult candidateExecuted
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  have entryOffset := List.all_eq_true.mp layout.1.2 entry member
  have offsetExact : entry.offset = offset := by
    rw [fieldExact, canonical] at entryOffset
    exact (Option.some.inj (beq_iff_eq.mp entryOffset)).symm
  have observed :
      ∀ address,
        nativeX87ReplayByteRange
            (source.outputAddress + BitVec.ofNat 32 offset) 4 address ->
          Engine.CandidateAddressObserved source.rep address := by
    intro address rangeMember
    rcases rangeMember with ⟨byte, byteBefore, rfl⟩
    apply Or.inl
    exact ⟨entry, member, byte, by simpa [fieldExact, width] using byteBefore, by
      simp [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
        BitVec.add_assoc]⟩
  have combinedDisjoint :
      CandidateFootprintsDisjoint
        (footprintUnion
          (nativeX87ReplayOutputWriteFootprint source.outputAddress)
          (nativeX87ReplayByteRange
            (source.frameAddress +
              BitVec.ofNat 32 nativeX87FrameStatusOffset) 4))
        (nativeX87ReplayByteRange
          (source.outputAddress + BitVec.ofNat 32 offset) 4) := by
    intro address writeMember readMember
    rcases writeMember with outputMember | statusMember
    · exact outputDisjoint address outputMember readMember
    · exact source.stackDisjoint address
        (nativeX87ReplayFrameByteRange_subset source.frameAddress
          nativeX87FrameStatusOffset 4 (by decide) address statusMember)
        (observed address readMember)
  have preserved :
      Engine.readBytes
          (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
            source.frameAddress captureInput).memory
          (source.outputAddress + BitVec.ofNat 32 offset) 4 =
        Engine.readBytes saved.memory
          (source.outputAddress + BitVec.ofNat 32 offset) 4 :=
    MemoryAgreesOutside.readBytes_of_disjoint frame combinedDisjoint
  rw [preserved]
  simpa only [saved, captureInput, width] using
    nativeX87ReplayFixedTemplateCaptureSavedState_readPresentFieldAtOffset
      runtimeTarget static originalPe caller logicalInput source imageBounded
      candidateResult candidateExecuted field offset canonical entry member
      fieldExact

private def nativeX87ReplayFixedTemplateCaptureWriteFootprint
    (logicalInput : MachineState) (frameAddress outputAddress : Word) :
    CandidateFootprint :=
  footprintUnion
    (nativeX87ReplayLogicalScratchFootprint logicalInput)
    (footprintUnion
      (nativeX87ReplayByteRange
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
        kernelX87FrameBytes)
      (footprintUnion
        (nativeX87ReplayOutputWriteFootprint outputAddress)
        (nativeX87ReplayByteRange
          (frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) 4)))

private theorem
    nativeX87ReplayFixedTemplateCaptureWriteDisjointPrivateStack
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
        source.frameAddress source.outputAddress)
      (nativeX87ReplayPrivateStackFootprint caller) := by
  intro address writeMember privateMember
  rcases writeMember with scratch | outputX87 | outputWrite | status
  · exact source.replayScratchDisjointPrivateStack address
      scratch privateMember
  · exact source.privateStackDisjointFrame address privateMember
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes (by decide)
        address outputX87)
  · exact source.privateStackDisjointRepresentation address privateMember
      (nativeX87ReplayOutputWriteFootprint_observed source address outputWrite)
  · exact source.privateStackDisjointFrame address privateMember
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameStatusOffset 4 (by decide) address status)

private theorem
    nativeX87ReplayFixedTemplateCaptureWriteDisjointPrivateEsp
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
        source.frameAddress source.outputAddress)
      (nativeX87ReplayByteRange
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) 4) := by
  intro address writeMember privateEsp
  have privateEspInFrame :=
    nativeX87ReplayFrameByteRange_subset source.frameAddress
      nativeX87FramePrivateEspOffset 4 (by decide) address privateEsp
  rcases writeMember with scratch | outputX87 | outputWrite | status
  · exact source.replayScratchDisjointFrame address scratch privateEspInFrame
  · exact
      (translatedByteRangesDisjoint source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes
        nativeX87FramePrivateEspOffset 4
        (by decide) (by decide) (Or.inr (by decide)))
        address outputX87 privateEsp
  · exact source.stackDisjoint address privateEspInFrame
      (nativeX87ReplayOutputWriteFootprint_observed source address outputWrite)
  · exact
      (translatedByteRangesDisjoint source.frameAddress
        nativeX87FrameStatusOffset 4 nativeX87FramePrivateEspOffset 4
        (by decide) (by decide) (Or.inr (by decide)))
        address status privateEsp

private theorem nativeX87ReplayFixedTemplateCaptureWriteDisjointImage
    {table : NativeX87ReplayBridgeTable} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {packs : List
      (NativeX87ReplayBridgeDescriptorPack pe imports relocations)}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {originalPe : PE32} {caller logicalInput : MachineState}
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintDisjointFromImage pe
      (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
        source.frameAddress source.outputAddress) := by
  intro address member
  rcases member with scratch | outputX87 | outputWrite | status
  · exact source.replayScratchDisjointImage address scratch
  · exact source.frameDisjointImage address
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes (by decide)
        address outputX87)
  · exact source.representationDisjointImage address
      (nativeX87ReplayOutputWriteFootprint_observed source address outputWrite)
  · exact source.frameDisjointImage address
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameStatusOffset 4 (by decide) address status)

private theorem nativeX87ReplayFixedTemplateCaptureWriteDisjointParent
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
        source.frameAddress source.outputAddress)
      (nativeX87ReplayByteRange
        (source.frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) 4) := by
  intro address member parent
  have parentInFrame :=
    nativeX87ReplayFrameByteRange_subset source.frameAddress
      nativeX87FrameParentOffset 4 (by decide) address parent
  rcases member with scratch | outputX87 | outputWrite | status
  · exact source.replayScratchDisjointFrame address scratch parentInFrame
  · exact
      (translatedByteRangesDisjoint source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes
        nativeX87FrameParentOffset 4 (by decide) (by decide)
        (Or.inr (by decide))) address outputX87 parent
  · exact source.stackDisjoint address parentInFrame
      (nativeX87ReplayOutputWriteFootprint_observed source address outputWrite)
  · exact
      (translatedByteRangesDisjoint source.frameAddress
        nativeX87FrameStatusOffset 4 nativeX87FrameParentOffset 4
        (by decide) (by decide) (Or.inr (by decide)))
        address status parent

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_memoryFrame
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    MemoryAgreesOutside
      (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
        source.frameAddress source.outputAddress)
      (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput).memory
      captureInput.memory := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let output :=
    nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
      source.frameAddress saved
  have entryEsp :
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).registers.esp =
      logicalInput.registers.esp := by
    exact congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller)
      candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have scratchFrame :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memoryFrame table pe
      logicalInput captureInput captureInputEsp
  have saveFrame :=
    nativeX87ReplayFixedTemplateCaptureSavedState_memoryFrame table pe
      source.frameAddress captureInput
  have outputLoaded :=
    nativeX87ReplayFixedTemplateCaptureSaved_outputLoaded runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have outputFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint source.outputAddress)
        output.memory saved.memory := by
    simpa [output, saved] using
      nativeX87ReplayFixedTemplateOutputWrittenState_memoryFrame undefinedSlot
        source.frameAddress source.outputAddress saved outputLoaded
  have active :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have beforeSaveEax :
      beforeSave.registers.get .eax = source.frameAddress := by
    simpa [beforeSave, Registers.get] using
      nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax table pe
        source.frameAddress captureInput active
  have savedEax : saved.registers.get .eax = source.frameAddress := by
    dsimp [saved]
    rw [nativeX87ReplayFixedTemplateCaptureSavedState_registers]
    exact beforeSaveEax
  have outputEax : output.registers.get .eax = source.frameAddress :=
    (nativeX87ReplayFixedTemplateOutputWrittenState_eax undefinedSlot
      source.frameAddress saved).trans savedEax
  have returnFrame :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) 4)
        (nativeX87ReplayFixedTemplateCaptureReturnEntryState
          source.frameAddress output).memory
        output.memory := by
    rw [nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory
      source.frameAddress output outputEax]
    exact MemoryAgreesOutside.write32ByteRange output.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset)
      (BitVec.ofNat 32 0)
  exact
    MemoryAgreesOutside.compose scratchFrame
      (MemoryAgreesOutside.compose saveFrame
        (MemoryAgreesOutside.compose outputFrame returnFrame))

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_returnAddress
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        (nativeX87ReplayPrivateStackByte caller 16) =
      BitVec.ofNat 32 (pe.imageBase + table.continuationRva) := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have frame :=
    nativeX87ReplayFixedTemplateCaptureFinalState_memoryFrame runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have disjointReturn :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
          source.frameAddress source.outputAddress)
        (nativeX87ReplayByteRange
          (nativeX87ReplayPrivateStackByte caller 16) 4) :=
    CandidateFootprintsDisjoint.mono
      (nativeX87ReplayFixedTemplateCaptureWriteDisjointPrivateStack source)
      (fun _ member => member)
      (by
        simpa [nativeX87ReplayPrivateStackByte] using
          nativeX87ReplayPrivateStackByteRange_subset caller 16 4 (by decide))
  calc
    _ = Memory.read32 captureInput.memory
        (nativeX87ReplayPrivateStackByte caller 16) :=
      MemoryAgreesOutside.read32_of_disjoint frame disjointReturn
    _ = BitVec.ofNat 32 (pe.imageBase + table.continuationRva) :=
      nativeX87ReplayFixedTemplateCaptureInput_returnAddress runtimeTarget
        static originalPe caller logicalInput source imageBounded
        candidateResult candidateExecuted

private theorem
    nativeX87ReplayFixedTemplateCaptureFinalState_privateStackPointer
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
      caller.registers.esp - BitVec.ofNat 32 20 := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have frame :=
    nativeX87ReplayFixedTemplateCaptureFinalState_memoryFrame runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  calc
    _ = Memory.read32 captureInput.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FramePrivateEspOffset) :=
      MemoryAgreesOutside.read32_of_disjoint frame
        (nativeX87ReplayFixedTemplateCaptureWriteDisjointPrivateEsp source)
    _ = caller.registers.esp - BitVec.ofNat 32 20 :=
      nativeX87ReplayFixedTemplateCaptureInput_privateStackPointer runtimeTarget
        static originalPe caller logicalInput source imageBounded
        candidateResult candidateExecuted

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_parent
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FrameParentOffset) =
      source.parentAddress := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have frame :=
    nativeX87ReplayFixedTemplateCaptureFinalState_memoryFrame runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have inputParent :=
    nativeX87ReplayFixedTemplateCaptureInput_readFrameCell runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted nativeX87FrameParentOffset source.parentAddress
      (by decide) (Or.inl (by decide)) source.parentBefore
  calc
    _ = Memory.read32 captureInput.memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FrameParentOffset) :=
      MemoryAgreesOutside.read32_of_disjoint frame
        (nativeX87ReplayFixedTemplateCaptureWriteDisjointParent source)
    _ = source.parentAddress := inputParent

private theorem nativeX87ReplayFixedTemplateCaptureInput_active
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32 captureInput.memory
        (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) =
      source.frameAddress := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have entryEsp :
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller).registers.esp =
      logicalInput.registers.esp :=
    congrArg Registers.esp
      (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
        originalPe caller logicalInput source imageBounded)
  have candidateEsp :
      candidateResult.state.registers.esp = logicalInput.registers.esp :=
    (executeX87Singleton_esp pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      (nativeX87ReplayFixedTemplateInstructionEntryState table pe
        source.inputCandidate caller)
      candidateResult candidateExecuted).trans entryEsp
  have captureInputEsp :
      captureInput.registers.esp = logicalInput.registers.esp := by
    simpa [captureInput] using candidateEsp
  have frame :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memoryFrame table pe
      logicalInput captureInput captureInputEsp
  have activeDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayLogicalScratchFootprint logicalInput)
        (nativeX87ReplayByteRange
          (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) 4) :=
    candidateFootprintDisjointFromImage_byteRange pe _ _
      4 source.replayScratchDisjointImage imageBounded
      (nativeX87ReplayActiveCellRvaBounded runtimeTarget)
  have active :
      Memory.read32
          (nativeX87ReplayPushRegState .eax
            (nativeX87ReplayPushFlagsState captureInput)).memory
          (BitVec.ofNat 32
            ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
        source.frameAddress :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have activeAddressExact :
      BitVec.ofNat 32
          ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32)) =
        BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva) :=
    wordOfNat_mod_wordSize _
  calc
    Memory.read32 captureInput.memory _ =
        Memory.read32
          (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
            captureInput).memory _ :=
      (MemoryAgreesOutside.read32_of_disjoint frame activeDisjoint).symm
    _ = Memory.read32
          (nativeX87ReplayPushRegState .eax
            (nativeX87ReplayPushFlagsState captureInput)).memory _ := by
      rw [nativeX87ReplayFixedTemplateCaptureBeforeSaveState_memory]
    _ = source.frameAddress := by
      rw [← activeAddressExact]
      exact active

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_active
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) =
      source.frameAddress := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have frame :=
    nativeX87ReplayFixedTemplateCaptureFinalState_memoryFrame runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have disjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
          source.frameAddress source.outputAddress)
        (nativeX87ReplayByteRange
          (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) 4) :=
    candidateFootprintDisjointFromImage_byteRange pe _ _
      4 (nativeX87ReplayFixedTemplateCaptureWriteDisjointImage source)
      imageBounded (nativeX87ReplayActiveCellRvaBounded runtimeTarget)
  calc
    _ = Memory.read32 captureInput.memory
        (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) :=
      MemoryAgreesOutside.read32_of_disjoint frame disjoint
    _ = source.frameAddress :=
      nativeX87ReplayFixedTemplateCaptureInput_active runtimeTarget static
        originalPe caller logicalInput source imageBounded candidateResult
        candidateExecuted

private theorem nativeX87ReplayFixedTemplateCaptureInput_target
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    runtimeTarget.target.descriptor.bridgeCell.Holds pe
      runtimeTarget.target.descriptor.bridge captureInput := by
  dsimp only
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have entryRegisters : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have entryFrame :=
    nativeX87ReplayFixedTemplateInstructionEntryState_memoryFrame runtimeTarget
      originalPe caller logicalInput source imageBounded
  have candidateFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        candidateResult.state.memory entry.memory := by
    exact executeX87Singleton_memoryFrame_of_sourceOperand pe
      (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
        runtimeTarget.addressMap.candidateInstructionRva)
      entry source.candidateInput candidateResult
      source.commandInput.candidateDescriptor candidateExecuted
      source.commandInput.candidateDecoded entryRegisters
  have captureInputMemory :
      captureInput.memory = candidateResult.state.memory := by
    simp [captureInput]
  let targetRange :=
    nativeX87ReplayByteRange
      (runtimeTarget.target.descriptor.bridgeCell.address pe) 4
  have targetBounded :=
    nativeX87ReplayBridgeCellRvaBounded runtimeTarget
  have entryDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateEntryWriteFootprint source)
        targetRange :=
    candidateFootprintDisjointFromImage_byteRange pe _ _
      4 (nativeX87ReplayFixedTemplateEntryWriteDisjointImage source)
      imageBounded targetBounded
  have operandDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOperandFootprint
          source.commandInput.candidateDescriptor source.candidateInput)
        targetRange := by
    intro address operandMember targetMember
    exact source.operandDisjointRuntimeCells address operandMember
      (Or.inr targetMember)
  constructor
  · exact source.targetBefore.1
  · calc
      Memory.read32 captureInput.memory
          (runtimeTarget.target.descriptor.bridgeCell.address pe) =
        Memory.read32 candidateResult.state.memory
          (runtimeTarget.target.descriptor.bridgeCell.address pe) := by
            rw [captureInputMemory]
      _ = Memory.read32 entry.memory
          (runtimeTarget.target.descriptor.bridgeCell.address pe) :=
        memoryAgreesOutside_read32_of_disjoint candidateFrame operandDisjoint
      _ = Memory.read32 caller.memory
          (runtimeTarget.target.descriptor.bridgeCell.address pe) :=
        memoryAgreesOutside_read32_of_disjoint entryFrame entryDisjoint
      _ = runtimeTarget.target.descriptor.bridge.address pe :=
        source.targetBefore.2

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_target
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    runtimeTarget.target.descriptor.bridgeCell.Holds pe
      runtimeTarget.target.descriptor.bridge
      (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput) := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  have inputTarget :=
    nativeX87ReplayFixedTemplateCaptureInput_target runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have frame :=
    nativeX87ReplayFixedTemplateCaptureFinalState_memoryFrame runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have disjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayFixedTemplateCaptureWriteFootprint logicalInput
          source.frameAddress source.outputAddress)
        (nativeX87ReplayByteRange
          (runtimeTarget.target.descriptor.bridgeCell.address pe) 4) :=
    candidateFootprintDisjointFromImage_byteRange pe _ _
      4 (nativeX87ReplayFixedTemplateCaptureWriteDisjointImage source)
      imageBounded (nativeX87ReplayBridgeCellRvaBounded runtimeTarget)
  constructor
  · exact inputTarget.1
  · calc
      _ = Memory.read32 captureInput.memory
          (runtimeTarget.target.descriptor.bridgeCell.address pe) :=
        MemoryAgreesOutside.read32_of_disjoint frame disjoint
      _ = runtimeTarget.target.descriptor.bridge.address pe :=
        inputTarget.2

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_esp
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
      source.frameAddress captureInput).registers.esp =
        nativeX87ReplayPrivateStackByte caller 16 := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let beforeSave :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let output :=
    nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
      source.frameAddress saved
  have active :=
    nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active runtimeTarget
      static originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have beforeSaveEax :
      beforeSave.registers.get .eax = source.frameAddress := by
    simpa [beforeSave, Registers.get] using
      nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax table pe
        source.frameAddress captureInput active
  have savedEax : saved.registers.get .eax = source.frameAddress := by
    exact (congrArg (fun registers => registers.get .eax)
      (nativeX87ReplayFixedTemplateCaptureSavedState_registers table pe
        source.frameAddress captureInput)).trans beforeSaveEax
  have outputEax : output.registers.get .eax = source.frameAddress :=
    (nativeX87ReplayFixedTemplateOutputWrittenState_eax undefinedSlot
      source.frameAddress saved).trans savedEax
  have finalPrivate :=
    nativeX87ReplayFixedTemplateCaptureFinalState_privateStackPointer
      runtimeTarget static originalPe caller logicalInput source imageBounded
      undefinedSlot candidateResult candidateExecuted
  have outputPrivate :
      Memory.read32 output.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
        caller.registers.esp - BitVec.ofNat 32 20 := by
    calc
      Memory.read32 output.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) =
        Memory.read32
          (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
            source.frameAddress captureInput).memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) := by
              change Memory.read32 output.memory _ =
                Memory.read32
                  (nativeX87ReplayFixedTemplateCaptureReturnEntryState
                    source.frameAddress output).memory _
              rw [nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory
                source.frameAddress output outputEax]
              exact
                (Memory.read32_write32_translated_of_disjoint output.memory
                  source.frameAddress nativeX87FrameStatusOffset
                  nativeX87FramePrivateEspOffset (BitVec.ofNat 32 0)
                  (by decide) (by decide) (Or.inr (by decide))).symm
      _ = caller.registers.esp - BitVec.ofNat 32 20 := finalPrivate
  calc
    (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput).registers.esp =
      (caller.registers.esp - BitVec.ofNat 32 20) +
        BitVec.ofNat 32 16 :=
      nativeX87ReplayFixedTemplateCaptureReturnEntryState_esp
        source.frameAddress
        (caller.registers.esp - BitVec.ofNat 32 20) output outputEax
        outputPrivate
    _ = nativeX87ReplayPrivateStackByte caller 16 := by
      rfl

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_returnEndpoint
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let returned :=
      nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput
    Memory.read32 returned.memory returned.registers.esp =
      BitVec.ofNat 32 (pe.imageBase + table.continuationRva) := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let returned :=
    nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
      source.frameAddress captureInput
  have returnedEsp :
      returned.registers.esp = nativeX87ReplayPrivateStackByte caller 16 :=
    nativeX87ReplayFixedTemplateCaptureFinalState_esp runtimeTarget static
      originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  rw [returnedEsp]
  exact nativeX87ReplayFixedTemplateCaptureFinalState_returnAddress
    runtimeTarget static originalPe caller logicalInput source imageBounded
    undefinedSlot candidateResult candidateExecuted

private theorem nativeX87ReplayFixedTemplateCaptureSavedState_outputEncoded
    (table : NativeX87ReplayBridgeTable) (pe : PE32)
    (frameAddress : Word) (input : MachineState)
    (outputValid :
      kernelX87FrameAddressValid
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset) = true) :
    Engine.readBytes
        (nativeX87ReplayFixedTemplateCaptureSavedState table pe frameAddress
          input).memory
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
        kernelX87FrameBytes =
      encodeKernelX87Frame input.x87Physical := by
  unfold nativeX87ReplayFixedTemplateCaptureSavedState
  rw [nativeX87ReplayFnSaveState_memory]
  have fits :
      (frameAddress +
          BitVec.ofNat 32 nativeX87FrameOutputX87Offset).toNat +
        kernelX87FrameBytes <= 2 ^ 32 := by
    simpa [kernelX87FrameAddressValid] using outputValid
  calc
    _ = encodeKernelX87Frame
        (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
          input).x87Physical := by
      simpa [encodeKernelX87Frame_length] using
        readBytes_writeX87FrameBytes
          (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
            input).memory
          (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          (encodeKernelX87Frame
            (nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe
              input).x87Physical)
          fits
    _ = encodeKernelX87Frame input.x87Physical := by
      rw [nativeX87ReplayFixedTemplateCaptureBeforeSaveState_x87Physical]

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_outputEncoded
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Engine.readBytes
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        (source.frameAddress +
          BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
        kernelX87FrameBytes =
      encodeKernelX87Frame candidateResult.state.x87Physical := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let output :=
    nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
      source.frameAddress saved
  have outputLoaded :=
    nativeX87ReplayFixedTemplateCaptureSaved_outputLoaded runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have outputFrame :
      MemoryAgreesOutside
        (nativeX87ReplayOutputWriteFootprint source.outputAddress)
        output.memory saved.memory := by
    simpa [output, saved] using
      nativeX87ReplayFixedTemplateOutputWrittenState_memoryFrame undefinedSlot
        source.frameAddress source.outputAddress saved outputLoaded
  have outputDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayOutputWriteFootprint source.outputAddress)
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          kernelX87FrameBytes) := by
    intro address outputMember frameMember
    exact source.stackDisjoint address
      (nativeX87ReplayFrameByteRange_subset source.frameAddress
        nativeX87FrameOutputX87Offset kernelX87FrameBytes (by decide)
        address frameMember)
      (nativeX87ReplayOutputWriteFootprint_observed source address outputMember)
  have savedEax :
      saved.registers.get .eax = source.frameAddress := by
    let beforeSave :=
      nativeX87ReplayFixedTemplateCaptureBeforeSaveState table pe captureInput
    have active :=
      nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active runtimeTarget
        static originalPe caller logicalInput source imageBounded candidateResult
        candidateExecuted
    have beforeSaveEax :
        beforeSave.registers.get .eax = source.frameAddress := by
      simpa [beforeSave, Registers.get] using
        nativeX87ReplayFixedTemplateCaptureBeforeSaveState_eax table pe
          source.frameAddress captureInput active
    exact (congrArg (fun registers => registers.get .eax)
      (nativeX87ReplayFixedTemplateCaptureSavedState_registers table pe
        source.frameAddress captureInput)).trans beforeSaveEax
  have outputEax : output.registers.get .eax = source.frameAddress :=
    (nativeX87ReplayFixedTemplateOutputWrittenState_eax undefinedSlot
      source.frameAddress saved).trans savedEax
  have returnFrame :
      MemoryAgreesOutside
        (nativeX87ReplayByteRange
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) 4)
        (nativeX87ReplayFixedTemplateCaptureReturnEntryState
          source.frameAddress output).memory
        output.memory := by
    rw [nativeX87ReplayFixedTemplateCaptureReturnEntryState_memory
      source.frameAddress output outputEax]
    exact MemoryAgreesOutside.write32ByteRange output.memory
      (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset)
      (BitVec.ofNat 32 0)
  have statusDisjoint :
      CandidateFootprintsDisjoint
        (nativeX87ReplayByteRange
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) 4)
        (nativeX87ReplayByteRange
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          kernelX87FrameBytes) :=
    translatedByteRangesDisjoint source.frameAddress nativeX87FrameStatusOffset 4
      nativeX87FrameOutputX87Offset kernelX87FrameBytes
      (by decide) (by decide) (Or.inl (by decide))
  calc
    Engine.readBytes
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory _ kernelX87FrameBytes =
      Engine.readBytes output.memory _ kernelX87FrameBytes :=
        MemoryAgreesOutside.readBytes_of_disjoint returnFrame statusDisjoint
    _ = Engine.readBytes saved.memory _ kernelX87FrameBytes :=
      MemoryAgreesOutside.readBytes_of_disjoint outputFrame outputDisjoint
    _ = encodeKernelX87Frame captureInput.x87Physical :=
      nativeX87ReplayFixedTemplateCaptureSavedState_outputEncoded table pe
        source.frameAddress captureInput source.outputX87FrameAddressValid
    _ = encodeKernelX87Frame candidateResult.state.x87Physical := by
      rw [nativeX87ReplayNopState_x87Physical]

private theorem nativeX87ReplayFixedTemplateCaptureFinalState_status
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    Memory.read32
        (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
          source.frameAddress captureInput).memory
        (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) =
      BitVec.ofNat 32 0 := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let saved :=
    nativeX87ReplayFixedTemplateCaptureSavedState table pe source.frameAddress
      captureInput
  let output :=
    nativeX87ReplayFixedTemplateOutputWrittenState undefinedSlot
      source.frameAddress saved
  have savedEax : saved.registers.get .eax = source.frameAddress :=
    nativeX87ReplayFixedTemplateCaptureSaved_eax runtimeTarget static
      originalPe caller logicalInput source imageBounded candidateResult
      candidateExecuted
  have outputEax : output.registers.get .eax = source.frameAddress :=
    (nativeX87ReplayFixedTemplateOutputWrittenState_eax undefinedSlot
      source.frameAddress saved).trans savedEax
  simpa only [nativeX87ReplayFixedTemplateCaptureFinalState, output, saved] using
    nativeX87ReplayFixedTemplateCaptureReturnEntryState_status
      source.frameAddress output outputEax

private theorem nativeX87ReplaySingletonFault_exact
    {candidatePe : PE32} {record : RawInstructionRecord}
    {input : MachineState} {result : StepResult}
    (witness : X87SingletonExecutionWitness candidatePe record input result) :
    witness.behavior.x87Fault = witness.effect.response.fault := by
  have executed := witness.executed
  unfold StageA.Relational.X87.executeSingletonCommand at executed
  rw [witness.decoded] at executed
  simp [normalizeCodeTarget, singletonTarget] at executed
  split at executed
  · rcases executed with ⟨_, _, _, behaviorExact⟩
    have behaviorExact := Option.some.inj behaviorExact
    have effectBound := witness.effectBound
    rw [← behaviorExact] at effectBound
    rw [← behaviorExact]
    have responseExact :=
      congrArg (fun effect => effect.map (·.response)) effectBound
    simp [StageA.Relational.X87.singletonBehavior] at responseExact
    exact congrArg StageA.X87.Response.fault responseExact
  · rcases executed with ⟨_, _, _, executed⟩
    cases addressExact :
        StageA.Relational.X87.commandDataAddress witness.descriptor input with
    | none => simp [addressExact] at executed
    | some address =>
        simp [addressExact] at executed
        have behaviorExact := executed
        have effectBound := witness.effectBound
        rw [← behaviorExact] at effectBound
        rw [← behaviorExact]
        have responseExact :=
          congrArg (fun effect => effect.map (·.response)) effectBound
        simp [StageA.Relational.X87.singletonBehavior] at responseExact
        exact congrArg StageA.X87.Response.fault responseExact

private theorem nativeX87ReplayMemoryEffectsRelated_append
    (addresses : NativeX87ReplayAddressMap)
    (originalLeft candidateLeft originalRight candidateRight :
      List MemoryEffect)
    (left :
      nativeX87ReplayMemoryEffectsRelated addresses originalLeft candidateLeft =
        true)
    (right :
      nativeX87ReplayMemoryEffectsRelated addresses originalRight candidateRight =
        true) :
    nativeX87ReplayMemoryEffectsRelated addresses
        (originalLeft ++ originalRight) (candidateLeft ++ candidateRight) =
      true := by
  induction originalLeft generalizing candidateLeft with
  | nil =>
      cases candidateLeft with
      | nil => simpa using right
      | cons _ _ => simp [nativeX87ReplayMemoryEffectsRelated] at left
  | cons original originalTail induction =>
      cases candidateLeft with
      | nil => simp [nativeX87ReplayMemoryEffectsRelated] at left
      | cons candidate candidateTail =>
          simp only [nativeX87ReplayMemoryEffectsRelated, Bool.and_eq_true] at left
          simp only [List.cons_append, nativeX87ReplayMemoryEffectsRelated,
            Bool.and_eq_true]
          exact ⟨left.1, induction candidateTail left.2⟩

private theorem nativeX87ReplayUsesMemoryOfExpectedOperand
    (command : StageA.X87.Command) (bytes : Nat)
    (expected : command.expectedOperandBytes = some bytes) :
    command.usesMemoryOperand = true := by
  cases command <;>
    simp [StageA.X87.Command.expectedOperandBytes,
      StageA.X87.Command.usesMemoryOperand] at expected ⊢

private theorem nativeX87ReplayExpectedOperandPositive
    (command : StageA.X87.Command) (bytes : Nat)
    (expected : command.expectedOperandBytes = some bytes) :
    0 < bytes := by
  cases command with
  | loadMemory format =>
      cases format <;>
        simp [StageA.X87.Command.expectedOperandBytes,
          StageA.X87.LoadFormat.byteWidth] at expected
      all_goals omega
  | binaryMemory operation format =>
      cases format <;>
        simp [StageA.X87.Command.expectedOperandBytes,
          StageA.X87.LoadFormat.byteWidth] at expected
      all_goals omega
  | loadControl =>
      simp [StageA.X87.Command.expectedOperandBytes] at expected
      omega
  | _ =>
      simp [StageA.X87.Command.expectedOperandBytes] at expected

private theorem nativeX87ReplayReadX87Word_eq_of_footprint
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (left right : MachineState)
    (address : Word) (addressExact :
      StageA.Relational.X87.commandDataAddress descriptor right =
        some address)
    (memory :
      ∀ byteAddress,
        nativeX87ReplayOperandFootprint descriptor right byteAddress ->
          left.memory byteAddress = right.memory byteAddress) :
    left.readX87Word address
        (descriptor.command.expectedOperandBytes.getD 0) =
      right.readX87Word address
        (descriptor.command.expectedOperandBytes.getD 0) := by
  let bytes := descriptor.command.expectedOperandBytes.getD 0
  have foldExact :
      ∀ (indices : List Nat) (accumulator : X87Word),
        (∀ index ∈ indices, index < bytes) ->
          indices.foldl (fun result index =>
              result ||| (BitVec.zeroExtend 80
                (left.memory
                  (address + BitVec.ofNat 32 index))).shiftLeft (index * 8))
              accumulator =
            indices.foldl (fun result index =>
              result ||| (BitVec.zeroExtend 80
                (right.memory
                  (address + BitVec.ofNat 32 index))).shiftLeft (index * 8))
              accumulator := by
    intro indices
    induction indices with
    | nil =>
        intro accumulator _bounded
        rfl
    | cons index tail induction =>
        intro accumulator bounded
        simp only [List.foldl_cons]
        rw [memory]
        · apply induction
          intro tailIndex tailMember
          exact bounded tailIndex (by simp [tailMember])
        · unfold nativeX87ReplayOperandFootprint
          rw [addressExact]
          exact ⟨index,
            Nat.lt_of_lt_of_le (bounded index (by simp))
              (Nat.le_max_left _ _), rfl⟩
  unfold MachineState.readX87Word
  apply foldExact
  intro index member
  exact List.mem_range.mp member

private theorem
    nativeX87ReplayFixedTemplateInstructionEntryState_commandInput
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32) :
    StageA.Relational.X87.commandStepInput pe
        runtimeTarget.addressMap.candidateInstructionRva
        source.commandInput.candidateDescriptor
        (nativeX87ReplayFixedTemplateInstructionEntryState table pe
          source.inputCandidate caller) =
      StageA.Relational.X87.commandStepInput pe
        runtimeTarget.addressMap.candidateInstructionRva
        source.commandInput.candidateDescriptor source.candidateInput := by
  let entry :=
    nativeX87ReplayFixedTemplateInstructionEntryState table pe
      source.inputCandidate caller
  have registers : entry.registers = source.candidateInput.registers :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_registers runtimeTarget
      originalPe caller logicalInput source imageBounded).trans
        source.candidateRegisters.symm
  have physical : entry.x87Physical = source.candidateInput.x87Physical :=
    (nativeX87ReplayFixedTemplateInstructionEntryState_x87Physical table pe
      source.inputCandidate caller).trans source.candidateX87.symm
  have dataAddress :
      StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor entry =
        StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor source.candidateInput := by
    unfold StageA.Relational.X87.commandDataAddress
    cases operand : source.commandInput.candidateDescriptor.memoryOperand with
    | none => simp [operand]
    | some addressing =>
        simp only [operand, Option.map_some]
        exact congrArg some
          (nativeX87ReplayEffectiveAddress_eq_of_registers addressing
            entry source.candidateInput registers)
  have operandBits :
      let bytes :=
        source.commandInput.candidateDescriptor.command.expectedOperandBytes.getD 0
      let entryAddress :=
        (StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor entry).getD
            entry.x87Physical.dataPointer
      let sourceAddress :=
        (StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor source.candidateInput).getD
            source.candidateInput.x87Physical.dataPointer
      (if bytes = 0 then BitVec.ofNat 80 0
        else entry.readX87Word entryAddress bytes) =
      (if bytes = 0 then BitVec.ofNat 80 0
        else source.candidateInput.readX87Word sourceAddress bytes) := by
    dsimp only
    have address :
        (StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor entry).getD
            entry.x87Physical.dataPointer =
        (StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor source.candidateInput).getD
            source.candidateInput.x87Physical.dataPointer := by
      rw [dataAddress, physical]
    rw [address]
    by_cases bytesZero :
        source.commandInput.candidateDescriptor.command.expectedOperandBytes.getD
          0 = 0
    · simp [bytesZero]
    simp only [if_neg bytesZero]
    cases sourceAddressExact :
        StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor source.candidateInput with
    | none =>
        cases expected :
            source.commandInput.candidateDescriptor.command.expectedOperandBytes with
        | none =>
            exact (bytesZero (by simp [expected])).elim
        | some bytes =>
            have usesMemory :=
              nativeX87ReplayUsesMemoryOfExpectedOperand
                source.commandInput.candidateDescriptor.command bytes expected
            have decodedMemory :=
              StageA.Relational.X87.decodeSingletonCommand_memoryOperand pe
                (replayInstructionRecordAt
                  runtimeTarget.target.descriptor.replay
                  runtimeTarget.addressMap.candidateInstructionRva).span
                source.commandInput.candidateDescriptor
                source.commandInput.candidateDecoded
            unfold StageA.Relational.X87.commandDataAddress at sourceAddressExact
            cases operand :
                source.commandInput.candidateDescriptor.memoryOperand with
            | none =>
                rw [usesMemory, operand] at decodedMemory
                contradiction
            | some addressing =>
                simp [operand] at sourceAddressExact
    | some addressValue =>
        exact nativeX87ReplayReadX87Word_eq_of_footprint
          source.commandInput.candidateDescriptor entry source.candidateInput
          addressValue sourceAddressExact
          (nativeX87ReplayFixedTemplateInstructionEntryState_memoryOnOperand
            runtimeTarget originalPe caller logicalInput source imageBounded)
  unfold StageA.Relational.X87.commandStepInput
  rw [dataAddress, physical]
  have operandBitsAtSource := operandBits
  dsimp only at operandBitsAtSource
  rw [dataAddress, physical] at operandBitsAtSource
  let makeInput : X87Word -> StageA.X87.StepInput := fun operand =>
    {
      operandBits := operand
      operandBytes :=
        source.commandInput.candidateDescriptor.command.expectedOperandBytes.getD 0
      opcode := source.commandInput.candidateDescriptor.opcode
      instructionPointer := BitVec.ofNat 32
        (pe.imageBase + runtimeTarget.addressMap.candidateInstructionRva)
      codeSelector := BitVec.ofNat 16 0
      dataPointer :=
        (StageA.Relational.X87.commandDataAddress
          source.commandInput.candidateDescriptor source.candidateInput).getD
            source.candidateInput.x87Physical.dataPointer
      dataSelector := BitVec.ofNat 16 0
    }
  change makeInput _ = makeInput _
  exact congrArg makeInput operandBitsAtSource

private structure ExactNativeX87ReplaySingletonPostFacts
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalResult candidateResult : StepResult) : Prop where
  faultFree : originalResult.faults = [] ∧ candidateResult.faults = []
  registers : originalResult.state.registers =
    candidateResult.state.registers
  eflags : originalResult.state.eflags =
    candidateResult.state.eflags
  memoryEffects :
    nativeX87ReplayMemoryEffectsRelated runtimeTarget.addressMap
      originalResult.memoryEffects candidateResult.memoryEffects = true
  physicalState :
    nativeX87ReplayPhysicalStatesRelatedChecked runtimeTarget.addressMap
      originalResult.state.x87Physical candidateResult.state.x87Physical = true

/-- All singleton post facts follow from the checked command-input relation and
the shared deterministic semantics.  No per-target execution authority appears
in this theorem. -/
private theorem exactNativeX87ReplaySingletonPostFacts
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (originalPe : PE32) (caller logicalInput candidateExecutionInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (candidatePhysicalInput :
      candidateExecutionInput.x87Physical =
        source.candidateInput.x87Physical)
    (candidateRegisters :
      candidateExecutionInput.registers = logicalInput.registers)
    (candidateEflags :
      candidateExecutionInput.eflags = logicalInput.eflags)
    (candidateCommandInput :
      StageA.Relational.X87.commandStepInput pe
          runtimeTarget.addressMap.candidateInstructionRva
          source.commandInput.candidateDescriptor candidateExecutionInput =
        StageA.Relational.X87.commandStepInput pe
          runtimeTarget.addressMap.candidateInstructionRva
          source.commandInput.candidateDescriptor source.candidateInput)
    (candidateSemantics :
      candidateExecutionInput.x87Semantics =
        source.candidateInput.x87Semantics)
    (originalResult candidateResult : StepResult)
    (originalExecuted :
      executeX87Singleton originalPe
          (replayInstructionRecord runtimeTarget.target.descriptor.replay)
          logicalInput =
        some originalResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt
            runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          candidateExecutionInput =
        some candidateResult) :
    ExactNativeX87ReplaySingletonPostFacts runtimeTarget originalResult
      candidateResult := by
  let originalRecord :=
    replayInstructionRecord runtimeTarget.target.descriptor.replay
  let candidateRecord :=
    replayInstructionRecordAt runtimeTarget.target.descriptor.replay
      runtimeTarget.addressMap.candidateInstructionRva
  let commandInput :
      X87SingletonCommandInputRelated runtimeTarget.addressMap.relation
        originalPe pe originalRecord candidateRecord logicalInput
        candidateExecutionInput := {
    originalDescriptor := source.commandInput.originalDescriptor
    candidateDescriptor := source.commandInput.candidateDescriptor
    originalDecoded := by
      simpa [originalRecord] using source.commandInput.originalDecoded
    candidateDecoded := by
      simpa [candidateRecord] using source.commandInput.candidateDecoded
    commandExact := source.commandInput.commandExact
    waitModeExact := source.commandInput.waitModeExact
    inputs := by
      change StageA.Relational.X87.InputRelated
        runtimeTarget.addressMap.relation
        (StageA.Relational.X87.commandStepInput originalPe
          runtimeTarget.target.descriptor.replay.rvaStart
          source.commandInput.originalDescriptor logicalInput)
        (StageA.Relational.X87.commandStepInput pe
          runtimeTarget.addressMap.candidateInstructionRva
          source.commandInput.candidateDescriptor candidateExecutionInput)
      rw [candidateCommandInput]
      simpa [originalRecord, candidateRecord, replayInstructionRecord,
        replayInstructionRecordAt] using source.commandInput.inputs
  }
  have states :
      StageA.Relational.X87.StateRelated runtimeTarget.addressMap.relation
        logicalInput.x87Physical candidateExecutionInput.x87Physical := by
    rw [candidatePhysicalInput, source.candidateX87]
    exact source.inputFrame.related
  have semantics :
      logicalInput.x87Semantics = candidateExecutionInput.x87Semantics :=
    source.engineRelated.shared_x87_semantics.trans candidateSemantics.symm
  obtain ⟨originalResponse, candidateResponse, originalResponseExact,
      candidateResponseExact, responses, physical⟩ :=
    executeX87Singleton_related runtimeTarget.addressMap.relation
      originalPe pe originalRecord candidateRecord logicalInput
      candidateExecutionInput originalResult candidateResult commandInput
      states semantics (by simpa [originalRecord] using originalExecuted)
      (by simpa [candidateRecord] using candidateExecuted)
  let originalWitness := executeX87Singleton_witness originalPe originalRecord
    logicalInput originalResult (by simpa [originalRecord] using originalExecuted)
  let candidateWitness := executeX87Singleton_witness pe candidateRecord
    candidateExecutionInput candidateResult
      (by simpa [candidateRecord] using candidateExecuted)
  have originalDescriptor :
      originalWitness.descriptor = source.commandInput.originalDescriptor := by
    rw [← Option.some.injEq, ← originalWitness.decoded]
    simpa [originalRecord] using source.commandInput.originalDecoded
  have candidateDescriptor :
      candidateWitness.descriptor = source.commandInput.candidateDescriptor := by
    rw [← Option.some.injEq, ← candidateWitness.decoded]
    simpa [candidateRecord] using source.commandInput.candidateDecoded
  have originalEffectResponse :
      originalWitness.effect.response = originalResponse := by
    rw [← Option.some.injEq, ← originalWitness.exactResponse,
      originalResponseExact]
  have candidateEffectResponse :
      candidateWitness.effect.response = candidateResponse := by
    rw [← Option.some.injEq, ← candidateWitness.exactResponse,
      candidateResponseExact]
  have originalFault :
      originalWitness.effect.response.fault = none := by
    rw [originalWitness.responseExecution, originalDescriptor]
    exact source.faultFree
  have candidateFault :
      candidateWitness.effect.response.fault = none := by
    calc
      candidateWitness.effect.response.fault =
          candidateResponse.fault := congrArg StageA.X87.Response.fault
            candidateEffectResponse
      _ = originalResponse.fault := responses.2.2.2.2.2.2.symm
      _ = originalWitness.effect.response.fault :=
        congrArg StageA.X87.Response.fault originalEffectResponse.symm
      _ = none := originalFault
  have originalFaultFree : originalResult.faults = [] := by
    rw [originalWitness.exactFault]
    rw [nativeX87ReplaySingletonFault_exact originalWitness, originalFault]
    rfl
  have candidateFaultFree : candidateResult.faults = [] := by
    rw [candidateWitness.exactFault]
    rw [nativeX87ReplaySingletonFault_exact candidateWitness, candidateFault]
    rfl
  refine {
    faultFree := ⟨originalFaultFree, candidateFaultFree⟩
    physicalState :=
      nativeX87ReplayPhysicalStatesRelatedChecked_complete
        runtimeTarget.addressMap originalResult.state.x87Physical
        candidateResult.state.x87Physical physical
    registers := ?_
    eflags := ?_
    memoryEffects := ?_
  }
  · rw [executeX87Singleton_registers originalPe originalRecord logicalInput
      originalResult (by simpa [originalRecord] using originalExecuted)]
    rw [executeX87Singleton_registers pe candidateRecord candidateExecutionInput
      candidateResult (by simpa [candidateRecord] using candidateExecuted)]
    rw [originalEffectResponse, candidateEffectResponse, candidateRegisters]
    unfold applyX87RegisterEffect
    rw [responses.2.2.1]
  · rw [executeX87Singleton_eflags originalPe originalRecord logicalInput
      originalResult (by simpa [originalRecord] using originalExecuted)]
    rw [executeX87Singleton_eflags pe candidateRecord candidateExecutionInput
      candidateResult (by simpa [candidateRecord] using candidateExecuted)]
    rw [originalEffectResponse, candidateEffectResponse, candidateEflags]
    unfold applyX87FlagsEffect
    rw [responses.2.2.2.1, responses.2.2.2.2.1]
  rw [originalWitness.orderedMemoryEffects,
    candidateWitness.orderedMemoryEffects]
  rcases commandInput.inputs with
    ⟨operandExact, _opcodeExact, _instructionExact, _codeSelectorExact,
      dataAddressExact, _dataSelectorExact⟩
  change
      (StageA.Relational.X87.commandStepInput originalPe
        runtimeTarget.target.descriptor.replay.rvaStart
        source.commandInput.originalDescriptor logicalInput).operand =
      (StageA.Relational.X87.commandStepInput pe
        runtimeTarget.addressMap.candidateInstructionRva
        source.commandInput.candidateDescriptor
        candidateExecutionInput).operand at operandExact
  change runtimeTarget.addressMap.relation.data
      (StageA.Relational.X87.commandStepInput originalPe
        runtimeTarget.target.descriptor.replay.rvaStart
        source.commandInput.originalDescriptor logicalInput).dataPointer
      (StageA.Relational.X87.commandStepInput pe
        runtimeTarget.addressMap.candidateInstructionRva
        source.commandInput.candidateDescriptor
        candidateExecutionInput).dataPointer at dataAddressExact
  have commandExact := commandInput.commandExact
  have responseStoreExact := responses.2.1
  have originalMemoryAddress :=
    nativeX87ReplaySingletonMemoryAddress_exact originalWitness
  have candidateMemoryAddress :=
    nativeX87ReplaySingletonMemoryAddress_exact candidateWitness
  rw [originalDescriptor] at originalMemoryAddress
  rw [candidateDescriptor] at candidateMemoryAddress
  have readEffects :
      nativeX87ReplayMemoryEffectsRelated runtimeTarget.addressMap
        (x87ReadEffects source.commandInput.originalDescriptor logicalInput)
        (x87ReadEffects source.commandInput.candidateDescriptor
          candidateExecutionInput) = true := by
    cases originalExpected :
        source.commandInput.originalDescriptor.command.expectedOperandBytes with
    | none =>
        have candidateExpected :
            source.commandInput.candidateDescriptor.command.expectedOperandBytes =
              none := by rw [← commandExact, originalExpected]
        simp [x87ReadEffects, originalExpected, candidateExpected,
          nativeX87ReplayMemoryEffectsRelated]
    | some bytes =>
        have candidateExpected :
            source.commandInput.candidateDescriptor.command.expectedOperandBytes =
              some bytes := by rw [← commandExact, originalExpected]
        have originalUsesMemory :
            source.commandInput.originalDescriptor.command.usesMemoryOperand =
              true :=
          nativeX87ReplayUsesMemoryOfExpectedOperand
            source.commandInput.originalDescriptor.command bytes originalExpected
        have bytesPositive : 0 < bytes :=
          nativeX87ReplayExpectedOperandPositive
            source.commandInput.originalDescriptor.command bytes originalExpected
        have candidateUsesMemory :
            source.commandInput.candidateDescriptor.command.usesMemoryOperand =
              true := by rw [← commandExact, originalUsesMemory]
        have originalOperandSome :
            source.commandInput.originalDescriptor.memoryOperand.isSome = true := by
          rw [← StageA.Relational.X87.decodeSingletonCommand_memoryOperand
            originalPe originalRecord.span source.commandInput.originalDescriptor
            commandInput.originalDecoded]
          exact originalUsesMemory
        have candidateOperandSome :
            source.commandInput.candidateDescriptor.memoryOperand.isSome = true := by
          rw [← StageA.Relational.X87.decodeSingletonCommand_memoryOperand
            pe candidateRecord.span source.commandInput.candidateDescriptor
            commandInput.candidateDecoded]
          exact candidateUsesMemory
        cases originalAddress :
            StageA.Relational.X87.commandDataAddress
              source.commandInput.originalDescriptor logicalInput with
        | none =>
            unfold StageA.Relational.X87.commandDataAddress at originalAddress
            cases source.commandInput.originalDescriptor.memoryOperand <;>
              simp_all
        | some originalAddressValue =>
            cases candidateAddress :
                StageA.Relational.X87.commandDataAddress
                  source.commandInput.candidateDescriptor
                  candidateExecutionInput with
            | none =>
                unfold StageA.Relational.X87.commandDataAddress at candidateAddress
                cases source.commandInput.candidateDescriptor.memoryOperand <;>
                  simp_all
            | some candidateAddressValue =>
                have relocated :
                    candidateAddressValue =
                      runtimeTarget.addressMap.relocateData
                        originalAddressValue := by
                  simpa [NativeX87ReplayAddressMap.relation,
                    StageA.Relational.X87.commandStepInput, originalExpected,
                    candidateExpected, originalAddress, candidateAddress] using
                      dataAddressExact
                have readValue :
                    candidateExecutionInput.readX87Word candidateAddressValue
                        bytes =
                      logicalInput.readX87Word originalAddressValue bytes := by
                  have bitsExact :=
                    congrArg StageA.X87.OperandInput.bits operandExact.symm
                  simpa [StageA.Relational.X87.commandStepInput,
                    originalExpected, candidateExpected, originalAddress,
                    candidateAddress, Nat.ne_of_gt bytesPositive] using bitsExact
                rw [relocated] at readValue
                simp [x87ReadEffects, originalExpected, candidateExpected,
                  originalAddress, candidateAddress,
                  nativeX87ReplayMemoryEffectRelated,
                  nativeX87ReplayMemoryEffectsRelated, relocated]
                exact readValue
  have writeEffects :
      nativeX87ReplayMemoryEffectsRelated runtimeTarget.addressMap
        (x87WriteEffects originalWitness.effect)
        (x87WriteEffects candidateWitness.effect) = true := by
    cases originalStore : originalWitness.effect.response.store with
    | none =>
        have candidateStore :
            candidateWitness.effect.response.store = none := by
          calc
            candidateWitness.effect.response.store = candidateResponse.store :=
              congrArg StageA.X87.Response.store candidateEffectResponse
            _ = originalResponse.store := responses.2.1.symm
            _ = originalWitness.effect.response.store :=
              congrArg StageA.X87.Response.store originalEffectResponse.symm
            _ = none := originalStore
        simp [x87WriteEffects, originalStore, candidateStore,
          nativeX87ReplayMemoryEffectsRelated]
    | some store =>
        have candidateStore :
            candidateWitness.effect.response.store = some store := by
          calc
            candidateWitness.effect.response.store = candidateResponse.store :=
              congrArg StageA.X87.Response.store candidateEffectResponse
            _ = originalResponse.store := responses.2.1.symm
            _ = originalWitness.effect.response.store :=
              congrArg StageA.X87.Response.store originalEffectResponse.symm
            _ = some store := originalStore
        have originalUsesMemory :
            source.commandInput.originalDescriptor.command.usesMemoryOperand =
              true := by
          have expected :
              source.commandInput.originalDescriptor.command.expectedStoreKind =
                some store.kind := by
            have originalResponseExecution := originalWitness.responseExecution
            rw [originalDescriptor] at originalResponseExecution
            have structurallyValid :=
              logicalInput.x87Semantics.execute_structurallyValid
                logicalInput.x87Semantics.complies
                source.commandInput.originalDescriptor.command
                source.commandInput.originalDescriptor.waitMode
                logicalInput.x87Physical
                (StageA.Relational.X87.commandStepInput originalPe
                  originalRecord.span.start
                  source.commandInput.originalDescriptor logicalInput)
                (StageA.Relational.X87.decodeSingletonCommand_waitModeValid
                  originalPe originalRecord.span
                  source.commandInput.originalDescriptor
                  commandInput.originalDecoded)
                (StageA.Relational.X87.commandStepInput_valid originalPe
                  originalRecord.span.start
                  source.commandInput.originalDescriptor logicalInput)
            rw [← originalResponseExecution] at structurallyValid
            unfold StageA.X87.Response.structurallyValid at structurallyValid
            rw [originalStore] at structurallyValid
            exact structurallyValid.1.symm
          exact StageA.X87.Command.usesMemoryOperand_of_expectedStoreKind
            source.commandInput.originalDescriptor.command store.kind expected
        have candidateUsesMemory :
            source.commandInput.candidateDescriptor.command.usesMemoryOperand =
              true := by rw [← commandExact, originalUsesMemory]
        have originalOperandSome :
            source.commandInput.originalDescriptor.memoryOperand.isSome = true := by
          rw [← StageA.Relational.X87.decodeSingletonCommand_memoryOperand
            originalPe originalRecord.span source.commandInput.originalDescriptor
            commandInput.originalDecoded]
          exact originalUsesMemory
        have candidateOperandSome :
            source.commandInput.candidateDescriptor.memoryOperand.isSome = true := by
          rw [← StageA.Relational.X87.decodeSingletonCommand_memoryOperand
            pe candidateRecord.span source.commandInput.candidateDescriptor
            commandInput.candidateDecoded]
          exact candidateUsesMemory
        cases originalAddress :
            StageA.Relational.X87.commandDataAddress
              source.commandInput.originalDescriptor logicalInput with
        | none =>
            unfold StageA.Relational.X87.commandDataAddress at originalAddress
            cases source.commandInput.originalDescriptor.memoryOperand <;>
              simp_all
        | some originalAddressValue =>
            cases candidateAddress :
                StageA.Relational.X87.commandDataAddress
                  source.commandInput.candidateDescriptor
                  candidateExecutionInput with
            | none =>
                unfold StageA.Relational.X87.commandDataAddress at candidateAddress
                cases source.commandInput.candidateDescriptor.memoryOperand <;>
                  simp_all
            | some candidateAddressValue =>
                have relocated :
                    candidateAddressValue =
                      runtimeTarget.addressMap.relocateData
                        originalAddressValue := by
                  simpa [NativeX87ReplayAddressMap.relation,
                    StageA.Relational.X87.commandStepInput, originalAddress,
                    candidateAddress] using dataAddressExact
                unfold x87WriteEffects
                rw [originalStore, candidateStore, originalMemoryAddress,
                  candidateMemoryAddress]
                simp [nativeX87ReplaySingletonMemoryAddress, originalStore,
                  candidateStore, originalAddress, candidateAddress,
                  nativeX87ReplayMemoryEffectRelated,
                  nativeX87ReplayMemoryEffectsRelated, relocated]
  rw [originalDescriptor, candidateDescriptor]
  exact nativeX87ReplayMemoryEffectsRelated_append runtimeTarget.addressMap
    _ _ _ _ readEffects writeEffects

private theorem
    nativeX87ReplayFixedTemplateCaptureFinalState_nonX87Output
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (originalResult candidateResult : StepResult)
    (originalExecuted :
      executeX87Singleton originalPe
          (replayInstructionRecord runtimeTarget.target.descriptor.replay)
          logicalInput =
        some originalResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (postFacts :
      ExactNativeX87ReplaySingletonPostFacts runtimeTarget originalResult
        candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    nativeX87ReplayNonX87OutputChecked
      source.toNativeX87ReplayBridgeSourceFrameEvidence
      (nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput)
      originalResult.state = true := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let final :=
    nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
      source.frameAddress captureInput
  have projection :
      NativeX87ReplayOutputProjection final.memory source.outputAddress
        candidateResult.state.registers candidateResult.state.eflags := by
    simpa only [final, captureInput] using
      nativeX87ReplayFixedTemplateCaptureFinalState_outputProjection
        runtimeTarget static originalPe caller logicalInput source imageBounded
        undefinedSlot candidateResult candidateExecuted
  have eaxBytes :
      some (Engine.readBytes final.memory source.outputAddress 4) =
        source.rep.fieldBytes originalResult.state
          runtimeTarget.target.descriptor.replay.rvaStart (.register .eax) := by
    have registerExact :
        candidateResult.state.registers.get .eax =
          originalResult.state.registers.get .eax :=
      (congrArg (fun registers => registers.get .eax) postFacts.registers).symm
    have readExact :=
      Engine.readBytes_eq_encodeLittleEndian4_of_read32 final.memory
        source.outputAddress originalResult.state.registers.eax
        (projection.eax.trans registerExact)
    simpa [Engine.EngineRep.fieldBytes, Engine.EngineField.byteWidth,
      Registers.get] using congrArg some readExact
  have eflagsBytes :
      some (Engine.readBytes final.memory
          (source.outputAddress + BitVec.ofNat 32 240) 4) =
        source.rep.fieldBytes originalResult.state
          runtimeTarget.target.descriptor.replay.rvaStart .eflags := by
    have readExact :=
      Engine.readBytes_eq_encodeLittleEndian4_of_read32 final.memory
        (source.outputAddress + BitVec.ofNat 32 240)
        originalResult.state.eflags
        (projection.eflags.trans postFacts.eflags.symm)
    simpa [Engine.EngineRep.fieldBytes, Engine.EngineField.byteWidth] using
      congrArg some readExact
  have flagBytes :
      ∀ (bit offset : Nat),
        Memory.read32 final.memory
            (source.outputAddress + BitVec.ofNat 32 offset) =
          BitVec.ofNat 32
            (candidateResult.state.eflags.extractLsb' bit 1).toNat ->
        some (Engine.readBytes final.memory
            (source.outputAddress + BitVec.ofNat 32 offset) 4) =
          source.rep.fieldBytes originalResult.state
            runtimeTarget.target.descriptor.replay.rvaStart (.flag bit) := by
    intro bit offset readExact
    have bitExact :
        candidateResult.state.eflags.extractLsb' bit 1 =
          originalResult.state.eflags.extractLsb' bit 1 :=
      congrArg (fun value => value.extractLsb' bit 1) postFacts.eflags.symm
    rw [bitExact] at readExact
    have encoded :=
      Engine.readBytes_eq_encodeLittleEndian4_of_read32 final.memory
        (source.outputAddress + BitVec.ofNat 32 offset)
        (BitVec.ofNat 32
          (originalResult.state.eflags.extractLsb' bit 1).toNat)
        readExact
    have valueBound :
        (originalResult.state.eflags.extractLsb' bit 1).toNat < 2 ^ 32 := by
      have oneBitBound :=
        (originalResult.state.eflags.extractLsb' bit 1).isLt
      omega
    have valueToNat :
        (BitVec.ofNat 32
          (originalResult.state.eflags.extractLsb' bit 1).toNat).toNat =
            (originalResult.state.eflags.extractLsb' bit 1).toNat := by
      rw [BitVec.toNat_ofNat]
      exact Nat.mod_eq_of_lt valueBound
    rw [valueToNat] at encoded
    simpa [Engine.EngineRep.fieldBytes, Engine.EngineField.byteWidth] using
      congrArg some encoded
  have layout := source.layoutCompatible
  unfold nativeX87ReplayEngineLayoutCompatible at layout
  simp only [Bool.and_eq_true] at layout
  unfold nativeX87ReplayNonX87OutputChecked
  apply List.all_eq_true.mpr
  intro entry member
  have canonical :=
    beq_iff_eq.mp (List.all_eq_true.mp layout.1.2 entry member)
  cases fieldExact : entry.field with
  | register register =>
      cases register with
      | eax =>
          have offsetExact : entry.offset = 0 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase,
            offsetExact] using eaxBytes
      | ebx =>
          have offsetExact : entry.offset = 4 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .ebx) 4 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 4 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .ebx (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
      | ecx =>
          have offsetExact : entry.offset = 8 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .ecx) 8 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 8 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .ecx (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
      | edx =>
          have offsetExact : entry.offset = 12 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .edx) 12 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 12 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .edx (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
      | esi =>
          have offsetExact : entry.offset = 16 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .esi) 16 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 16 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .esi (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
      | edi =>
          have offsetExact : entry.offset = 20 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .edi) 20 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 20 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .edi (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
      | ebp =>
          have offsetExact : entry.offset = 24 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .ebp) 24 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 24 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .ebp (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
      | esp =>
          have offsetExact : entry.offset = 28 := by
            rw [fieldExact] at canonical
            exact (Option.some.inj canonical).symm
          have read :=
            nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
              runtimeTarget static originalPe caller logicalInput source
              imageBounded undefinedSlot candidateResult candidateExecuted
              (.register .esp) 28 (by decide) (by decide) entry member fieldExact
              (nativeX87ReplayOutputWriteFootprint_disjointOffset
                source.outputAddress 28 (by decide) (by decide))
          have registerExact :=
            executeX87Singleton_register_other originalPe
              (replayInstructionRecord runtimeTarget.target.descriptor.replay)
              logicalInput originalResult originalExecuted .esp (by decide)
          simp only [fieldExact, nativeX87ReplaySeparateFrameField,
            Bool.false_or, beq_iff_eq]
          simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
            Engine.EngineRep.fieldBytes, registerExact] using read
  | eflags =>
      have offsetExact : entry.offset = 240 := by
        rw [fieldExact] at canonical
        exact (Option.some.inj canonical).symm
      simp only [fieldExact, nativeX87ReplaySeparateFrameField,
        Bool.false_or, beq_iff_eq]
      simpa [Engine.EngineFieldLayout.address, source.engineBase,
        offsetExact] using eflagsBytes
  | flag bit =>
      have writtenFlag :
          ∀ (flagBit offset : Nat),
            entry.field = .flag flagBit ->
            entry.offset = offset ->
            Memory.read32 final.memory
                (source.outputAddress + BitVec.ofNat 32 offset) =
              BitVec.ofNat 32
                (candidateResult.state.eflags.extractLsb' flagBit 1).toNat ->
            (nativeX87ReplaySeparateFrameField entry.field ||
              some (Engine.readBytes final.memory
                (entry.address source.rep.engineBase) entry.field.byteWidth) ==
                  source.rep.fieldBytes originalResult.state
                    runtimeTarget.target.descriptor.replay.rvaStart entry.field) =
              true := by
        intro flagBit offset entryField offsetExact readExact
        simp only [entryField, nativeX87ReplaySeparateFrameField,
          Bool.false_or, beq_iff_eq]
        simpa [Engine.EngineFieldLayout.address, source.engineBase,
          offsetExact] using flagBytes flagBit offset readExact
      have alternatives :
          bit = 0 ∨ bit = 2 ∨ bit = 6 ∨ bit = 7 ∨ bit = 10 ∨ bit = 11 := by
        by_cases bit0 : bit = 0
        · exact Or.inl bit0
        by_cases bit2 : bit = 2
        · exact Or.inr (Or.inl bit2)
        by_cases bit6 : bit = 6
        · exact Or.inr (Or.inr (Or.inl bit6))
        by_cases bit7 : bit = 7
        · exact Or.inr (Or.inr (Or.inr (Or.inl bit7)))
        by_cases bit10 : bit = 10
        · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl bit10))))
        by_cases bit11 : bit = 11
        · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr bit11))))
        rw [fieldExact] at canonical
        simp [nativeX87ReplayEngineFieldOffset?, bit0, bit2, bit6, bit7,
          bit10, bit11] at canonical
      rcases alternatives with
        rfl | rfl | rfl | rfl | rfl | rfl
      · have offsetExact : entry.offset = 32 := by
          rw [fieldExact] at canonical
          exact (Option.some.inj canonical).symm
        simpa only [final, captureInput, fieldExact] using
          writtenFlag 0 32 fieldExact offsetExact projection.carry
      · have offsetExact : entry.offset = 48 := by
          rw [fieldExact] at canonical
          exact (Option.some.inj canonical).symm
        simpa only [final, captureInput, fieldExact] using
          writtenFlag 2 48 fieldExact offsetExact projection.parity
      · have offsetExact : entry.offset = 36 := by
          rw [fieldExact] at canonical
          exact (Option.some.inj canonical).symm
        simpa only [final, captureInput, fieldExact] using
          writtenFlag 6 36 fieldExact offsetExact projection.zero
      · have offsetExact : entry.offset = 40 := by
          rw [fieldExact] at canonical
          exact (Option.some.inj canonical).symm
        simpa only [final, captureInput, fieldExact] using
          writtenFlag 7 40 fieldExact offsetExact projection.sign
      · have offsetExact : entry.offset = 52 := by
          rw [fieldExact] at canonical
          exact (Option.some.inj canonical).symm
        have read :=
          nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
            runtimeTarget static originalPe caller logicalInput source
            imageBounded undefinedSlot candidateResult candidateExecuted
            (.flag 10) 52 (by decide) (by decide) entry member fieldExact
            (nativeX87ReplayOutputWriteFootprint_disjointOffset
              source.outputAddress 52 (by decide) (by decide))
        have directionExact :=
          executeX87Singleton_directionFlag originalPe
            (replayInstructionRecord runtimeTarget.target.descriptor.replay)
            logicalInput originalResult originalExecuted
        simp only [fieldExact, nativeX87ReplaySeparateFrameField,
          Bool.false_or, beq_iff_eq]
        simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
          Engine.EngineRep.fieldBytes, directionExact] using read
      · have offsetExact : entry.offset = 44 := by
          rw [fieldExact] at canonical
          exact (Option.some.inj canonical).symm
        simpa only [final, captureInput, fieldExact] using
          writtenFlag 11 44 fieldExact offsetExact projection.overflow
  | fsBase =>
      have offsetExact : entry.offset = 244 := by
        rw [fieldExact] at canonical
        exact (Option.some.inj canonical).symm
      have read :=
        nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
          runtimeTarget static originalPe caller logicalInput source imageBounded
          undefinedSlot candidateResult candidateExecuted .fsBase 244 (by decide)
          (by decide) entry member fieldExact
          (nativeX87ReplayOutputWriteFootprint_disjointOffset
            source.outputAddress 244 (by decide) (by decide))
      have fsBaseExact :=
        executeX87Singleton_fsBase originalPe
          (replayInstructionRecord runtimeTarget.target.descriptor.replay)
          logicalInput originalResult originalExecuted
      simp only [fieldExact, nativeX87ReplaySeparateFrameField,
        Bool.false_or, beq_iff_eq]
      simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
        Engine.EngineRep.fieldBytes, fsBaseExact] using read
  | x87Stack index =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87Empty index =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87Tag index =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87Control =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87Status =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87PendingException =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87LastOpcode =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87InstructionPointer =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87CodeSelector =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87DataPointer =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | x87DataSelector =>
      simp [fieldExact, nativeX87ReplaySeparateFrameField]
  | originalRva =>
      have offsetExact : entry.offset = 248 := by
        rw [fieldExact] at canonical
        exact (Option.some.inj canonical).symm
      have read :=
        nativeX87ReplayFixedTemplateCaptureFinalState_readPresentFieldAtOffset
          runtimeTarget static originalPe caller logicalInput source imageBounded
          undefinedSlot candidateResult candidateExecuted .originalRva 248
          (by decide) (by decide) entry member fieldExact
          (nativeX87ReplayOutputWriteFootprint_disjointOffset
            source.outputAddress 248 (by decide) (by decide))
      simp only [fieldExact, nativeX87ReplaySeparateFrameField,
        Bool.false_or, beq_iff_eq]
      simpa [Engine.EngineFieldLayout.address, source.engineBase, offsetExact,
        Engine.EngineRep.fieldBytes] using read

private theorem exactNativeX87ReplayCheckedPostFrame_returned_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput)
    (imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (undefinedSlot : Nat) (originalResult candidateResult : StepResult)
    (originalExecuted :
      executeX87Singleton originalPe
          (replayInstructionRecord runtimeTarget.target.descriptor.replay)
          logicalInput =
        some originalResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          (nativeX87ReplayFixedTemplateInstructionEntryState table pe
            source.inputCandidate caller) =
        some candidateResult)
    (postFacts :
      ExactNativeX87ReplaySingletonPostFacts runtimeTarget originalResult
        candidateResult) :
    let captureInput :=
      nativeX87ReplayNopState
        (nativeX87ReplayFixedTemplateInstructionRegionSize -
          static.candidateDescriptor.size)
        candidateResult.state
    let final :=
      nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
        source.frameAddress captureInput
    let returned := nativeX87ReplayRetState final
    (exactNativeX87ReplayCheckedPostFrame? runtimeTarget source returned
      originalResult candidateResult).isSome = true := by
  dsimp only
  let captureInput :=
    nativeX87ReplayNopState
      (nativeX87ReplayFixedTemplateInstructionRegionSize -
        static.candidateDescriptor.size)
      candidateResult.state
  let final :=
    nativeX87ReplayFixedTemplateCaptureFinalState table pe undefinedSlot
      source.frameAddress captureInput
  let returned := nativeX87ReplayRetState final
  have targetFinal :=
    nativeX87ReplayFixedTemplateCaptureFinalState_target runtimeTarget static
      originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have targetAfter :
      runtimeTarget.target.descriptor.bridgeCell.Holds pe
        runtimeTarget.target.descriptor.bridge returned := by
    exact ⟨targetFinal.1, by simpa [returned, final, captureInput] using
      targetFinal.2⟩
  have activeFinal :=
    nativeX87ReplayFixedTemplateCaptureFinalState_active runtimeTarget static
      originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have activeAfter :
      Memory.read32 returned.memory
          (BitVec.ofNat 32 (pe.imageBase + table.activeFramePointerRva)) =
        source.frameAddress := by
    simpa [returned, final, captureInput] using activeFinal
  have parentFinal :=
    nativeX87ReplayFixedTemplateCaptureFinalState_parent runtimeTarget static
      originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have parentAfter :
      Memory.read32 returned.memory
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameParentOffset) =
        source.parentAddress := by
    simpa [returned, final, captureInput] using parentFinal
  have privateFinal :=
    nativeX87ReplayFixedTemplateCaptureFinalState_privateStackPointer
      runtimeTarget static originalPe caller logicalInput source imageBounded
      undefinedSlot candidateResult candidateExecuted
  have privateStackEstablished :
      Memory.read32 returned.memory
          (source.frameAddress +
            BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
        BitVec.ofNat 32 0 := by
    have finalNonzero :
        Memory.read32 final.memory
            (source.frameAddress +
              BitVec.ofNat 32 nativeX87FramePrivateEspOffset) !=
          BitVec.ofNat 32 0 := by
      rw [privateFinal]
      exact source.privateStackPointerNonzero
    simpa [returned] using finalNonzero
  have statusFinal :=
    nativeX87ReplayFixedTemplateCaptureFinalState_status runtimeTarget static
      originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have statusSucceeded :
      Memory.read32 returned.memory
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameStatusOffset) =
        BitVec.ofNat 32 0 := by
    simpa [returned, final, captureInput] using statusFinal
  have nonX87Final :=
    nativeX87ReplayFixedTemplateCaptureFinalState_nonX87Output runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      originalResult candidateResult originalExecuted candidateExecuted postFacts
  have nonX87Output :
      nativeX87ReplayNonX87OutputChecked
        source.toNativeX87ReplayBridgeSourceFrameEvidence returned
        originalResult.state = true := by
    simpa [returned, final, captureInput,
      nativeX87ReplayNonX87OutputChecked] using nonX87Final
  have outputFinal :=
    nativeX87ReplayFixedTemplateCaptureFinalState_outputEncoded runtimeTarget
      static originalPe caller logicalInput source imageBounded undefinedSlot
      candidateResult candidateExecuted
  have outputEncoded :
      Engine.readBytes returned.memory
          (source.frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset)
          kernelX87FrameBytes =
        encodeKernelX87Frame candidateResult.state.x87Physical := by
    simpa [returned, final, captureInput] using outputFinal
  dsimp only [returned, final, captureInput] at targetAfter activeAfter parentAfter privateStackEstablished statusSucceeded nonX87Output outputEncoded
  unfold exactNativeX87ReplayCheckedPostFrame?
  rw [dif_pos targetAfter.2, dif_pos activeAfter, dif_pos parentAfter,
    dif_pos privateStackEstablished, dif_pos statusSucceeded,
    dif_pos postFacts.faultFree, dif_pos nonX87Output,
    dif_pos postFacts.memoryEffects, dif_pos postFacts.physicalState,
    dif_pos outputEncoded]
  rfl

private theorem exactNativeX87ReplayFixedTemplateInstructionRun
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programPe : program.pe = pe) (programImports : program.imports = imports)
    (undefinedSlot : Nat) (input : MachineState)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          input =
        some candidateResult)
    (faultFree : candidateResult.faults = [])
    (calls : List NativeCallFrame) :
    runRelatedSteps program.transitionSystem static.schedule.instructionFuel
        (.running runtimeTarget.target.frameMapping.instructionRva
          undefinedSlot input calls 0 [] RelationalWorld.empty []) =
      (.running runtimeTarget.target.frameMapping.captureRva
        (undefinedSlot + static.schedule.instructionFuel)
        (nativeX87ReplayNopState
          (nativeX87ReplayFixedTemplateInstructionRegionSize -
            static.candidateDescriptor.size)
          candidateResult.state)
        calls 0 [] RelationalWorld.empty [], []) := by
  subst pe
  subst imports
  have rolesExact := static.semanticShape.instruction
  have phaseLength :=
    kernelMixedReplayTemplateRoles?_length static.mixedReplay.instruction
      (nativeX87ReplayFixedTemplateInstructionRoles
        runtimeTarget.target.frameMapping static.semanticPlan.command)
      rolesExact
  have executed :=
    nativeX87ReplayFixedTemplateInstructionRoles_running runtimeTarget static
      undefinedSlot input candidateResult candidateExecuted faultFree
  cases entriesExact : static.mixedReplay.instruction with
  | nil =>
      have impossible := rolesExact
      simp [entriesExact, kernelMixedReplayTemplateRoles?,
        nativeX87ReplayFixedTemplateInstructionRoles] at impossible
  | cons first tail =>
      have firstRva := kernelMixedReplayTemplateRoles?_head_rva first tail
        (.x87Command runtimeTarget.target.frameMapping.instructionRva
          static.semanticPlan.command)
        (nativeX87ReplayFixedTemplateInstructionRoles
          runtimeTarget.target.frameMapping
          static.semanticPlan.command).tail
        (by
          simpa [entriesExact,
            nativeX87ReplayFixedTemplateInstructionRoles] using rolesExact)
      have firstRvaExact :
          first.instruction.rva =
            runtimeTarget.target.frameMapping.instructionRva := by
        simpa [NativeX87ReplayTemplateRole.rva] using firstRva
      have phase :=
        exactNativeX87ReplayPhaseRun_of_roles program
          static.mixedReplay.instruction first tail entriesExact
          (nativeX87ReplayFixedTemplateInstructionRoles
            runtimeTarget.target.frameMapping static.semanticPlan.command)
          rolesExact undefinedSlot
          (undefinedSlot + static.mixedReplay.instruction.length)
          runtimeTarget.target.frameMapping.captureRva input
          (nativeX87ReplayNopState
            (nativeX87ReplayFixedTemplateInstructionRegionSize -
              static.candidateDescriptor.size)
            candidateResult.state)
          calls (by
            simpa [phaseLength] using executed)
      rw [static.instructionFuelExact, ← firstRvaExact]
      exact phase

private theorem exactNativeX87ReplayFixedTemplateInstructionEndpoint_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programPe : program.pe = pe) (programImports : program.imports = imports)
    (undefinedSlot : Nat) (input : MachineState)
    (candidateResult : StepResult)
    (candidateExecuted :
      executeX87Singleton pe
          (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
            runtimeTarget.addressMap.candidateInstructionRva)
          input =
        some candidateResult)
    (faultFree : candidateResult.faults = [])
    (calls : List NativeCallFrame) :
    (exactNativeX87ReplaySilentRunningEndpoint?
      (runRelatedSteps program.transitionSystem static.schedule.instructionFuel
        (.running runtimeTarget.target.frameMapping.instructionRva
          undefinedSlot input calls 0 [] RelationalWorld.empty []))
      runtimeTarget.target.frameMapping.captureRva
      (undefinedSlot + static.schedule.instructionFuel) calls).isSome = true := by
  rw [exactNativeX87ReplayFixedTemplateInstructionRun runtimeTarget static
    program programPe programImports undefinedSlot input candidateResult
    candidateExecuted faultFree calls]
  simp [exactNativeX87ReplaySilentRunningEndpoint?]

private theorem exactNativeX87ReplayFixedTemplateCaptureRun
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programPe : program.pe = pe) (programImports : program.imports = imports)
    (undefinedSlot : Nat) (frameAddress : Word) (input : MachineState)
    (active :
      Memory.read32
          (nativeX87ReplayPushRegState .eax
            (nativeX87ReplayPushFlagsState input)).memory
          (BitVec.ofNat 32
            ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
        frameAddress)
    (outputValid :
      kernelX87FrameAddressValid
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset) = true)
    (calls : List NativeCallFrame) :
    runRelatedSteps program.transitionSystem static.schedule.captureFuel
        (.running runtimeTarget.target.frameMapping.captureRva
          undefinedSlot input calls 0 [] RelationalWorld.empty []) =
      (.running runtimeTarget.target.frameMapping.returnRva
        (undefinedSlot + static.schedule.captureFuel)
        (nativeX87ReplayFixedTemplateCaptureFinalState table program.pe
          undefinedSlot frameAddress input)
        calls 0 [] RelationalWorld.empty [], []) := by
  subst pe
  subst imports
  have rolesExact := static.semanticShape.capture
  have phaseLength :=
    kernelMixedReplayTemplateRoles?_length static.mixedReplay.capture
      (nativeX87ReplayFixedTemplateCaptureRoles table program.pe
        runtimeTarget.target.frameMapping)
      rolesExact
  have executed :=
    nativeX87ReplayFixedTemplateCaptureRoles_running runtimeTarget
      undefinedSlot frameAddress input active outputValid
  cases entriesExact : static.mixedReplay.capture with
  | nil =>
      have impossible := rolesExact
      simp [entriesExact, kernelMixedReplayTemplateRoles?,
        nativeX87ReplayFixedTemplateCaptureRoles] at impossible
  | cons first tail =>
      have firstRva := kernelMixedReplayTemplateRoles?_head_rva first tail
        (.ordinary runtimeTarget.target.frameMapping.captureRva .pushFlags 1)
        (nativeX87ReplayFixedTemplateCaptureRoles table program.pe
          runtimeTarget.target.frameMapping).tail
        (by
          simpa [entriesExact,
            nativeX87ReplayFixedTemplateCaptureRoles] using rolesExact)
      have firstRvaExact :
          first.instruction.rva =
            runtimeTarget.target.frameMapping.captureRva := by
        simpa [NativeX87ReplayTemplateRole.rva] using firstRva
      have phase :=
        exactNativeX87ReplayPhaseRun_of_roles program
          static.mixedReplay.capture first tail entriesExact
          (nativeX87ReplayFixedTemplateCaptureRoles table program.pe
            runtimeTarget.target.frameMapping)
          rolesExact undefinedSlot
          (undefinedSlot + static.mixedReplay.capture.length)
          runtimeTarget.target.frameMapping.returnRva input
          (nativeX87ReplayFixedTemplateCaptureFinalState table program.pe
            undefinedSlot frameAddress input)
          calls (by simpa [phaseLength] using executed)
      rw [static.captureFuelExact, ← firstRvaExact]
      exact phase

private theorem exactNativeX87ReplayFixedTemplateCaptureEndpoint_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programPe : program.pe = pe) (programImports : program.imports = imports)
    (undefinedSlot : Nat) (frameAddress : Word) (input : MachineState)
    (active :
      Memory.read32
          (nativeX87ReplayPushRegState .eax
            (nativeX87ReplayPushFlagsState input)).memory
          (BitVec.ofNat 32
            ((pe.imageBase + table.activeFramePointerRva) % (2 ^ 32))) =
        frameAddress)
    (outputValid :
      kernelX87FrameAddressValid
        (frameAddress + BitVec.ofNat 32 nativeX87FrameOutputX87Offset) = true)
    (calls : List NativeCallFrame) :
    (exactNativeX87ReplaySilentRunningEndpoint?
      (runRelatedSteps program.transitionSystem static.schedule.captureFuel
        (.running runtimeTarget.target.frameMapping.captureRva
          undefinedSlot input calls 0 [] RelationalWorld.empty []))
      runtimeTarget.target.frameMapping.returnRva
      (undefinedSlot + static.schedule.captureFuel) calls).isSome = true := by
  rw [exactNativeX87ReplayFixedTemplateCaptureRun runtimeTarget static program
    programPe programImports undefinedSlot frameAddress input active outputValid
    calls]
  simp [exactNativeX87ReplaySilentRunningEndpoint?]

/-- A checked singleton mixed-replay return consumes exactly the admitted
native call frame.  This is the stopped-path counterpart of
`runRelatedSteps_mixedReplay_running`; it keeps nested call/return composition
inside the exact transition system. -/
private theorem runRelatedSteps_mixedReplay_return
    (program : ExactNestedNativeWorldProgram)
    (instruction : KernelMixedReplayInstruction)
    (undefinedSlot : Nat) (input after : MachineState)
    (frame : NativeCallFrame) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime)
    (executed :
      runKernelMixedReplayConcrete program.pe program.imports undefinedSlot input
          [instruction] =
        .stopped (.returned frame.returnAddress) after) :
    runRelatedSteps program.transitionSystem 1
        (.running instruction.rva undefinedSlot input (frame :: calls)
          eventIndex events world externalFrames) =
      (.running frame.continuationRva 0 after calls eventIndex events world
        externalFrames, []) := by
  simp only [runKernelMixedReplayConcrete] at executed
  simp [runRelatedSteps, ExactNestedNativeWorldProgram.transitionSystem,
    stepPE32NestedNativeWorldExecution, executed,
    transitionFromNestedNativeWorldOutcome]

private theorem nativeX87ReplayFixedTemplateReturnRoles_stopped
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (undefinedSlot : Nat) (input : MachineState) :
    runNativeX87ReplayTemplateRoles pe imports undefinedSlot input
        (nativeX87ReplayFixedTemplateReturnRoles
          runtimeTarget.target.frameMapping) =
      .stopped
        (.returned (Memory.read32 input.memory input.registers.esp))
        (nativeX87ReplayRetState input) := by
  simp [nativeX87ReplayFixedTemplateReturnRoles,
    runNativeX87ReplayTemplateRoles,
    NativeX87ReplayTemplateRole.semanticStep_ret]

private theorem exactNativeX87ReplayFixedTemplateReturnRun
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programPe : program.pe = pe) (programImports : program.imports = imports)
    (undefinedSlot : Nat) (input : MachineState)
    (returnAddressExact :
      Memory.read32 input.memory input.registers.esp =
        BitVec.ofNat 32 (program.pe.imageBase + table.continuationRva))
    (calls : List NativeCallFrame) :
    runRelatedSteps program.transitionSystem static.schedule.returnFuel
        (.running runtimeTarget.target.frameMapping.returnRva undefinedSlot
          input
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          0 [] RelationalWorld.empty []) =
      (.running table.continuationRva 0 (nativeX87ReplayRetState input)
        calls 0 [] RelationalWorld.empty [], []) := by
  subst pe
  subst imports
  have rolesExact := static.semanticShape.returnPath
  have phaseLength :=
    kernelMixedReplayTemplateRoles?_length static.mixedReplay.returnPath
      (nativeX87ReplayFixedTemplateReturnRoles
        runtimeTarget.target.frameMapping)
      rolesExact
  have semanticExact :=
    runKernelMixedReplaySemantic_eq_templateRoles static.mixedReplay.returnPath
      (nativeX87ReplayFixedTemplateReturnRoles
        runtimeTarget.target.frameMapping)
      rolesExact undefinedSlot input
  have concreteExact :=
    runKernelMixedReplayConcrete_composes program.pe program.imports
      (checkedKernelMixedReplayInstructions static.mixedReplay.returnPath)
      (checkedKernelMixedReplayInstructions_exact static.mixedReplay.returnPath)
      undefinedSlot input
  have semanticStopped :=
    nativeX87ReplayFixedTemplateReturnRoles_stopped runtimeTarget
      undefinedSlot input
  cases entriesExact : static.mixedReplay.returnPath with
  | nil =>
      have impossible := rolesExact
      simp [entriesExact, kernelMixedReplayTemplateRoles?,
        nativeX87ReplayFixedTemplateReturnRoles] at impossible
  | cons first tail =>
      cases tail with
      | nil =>
          have concreteStopped :
              runKernelMixedReplayConcrete program.pe program.imports
                  undefinedSlot input [first.instruction] =
                .stopped
                  (.returned
                    (BitVec.ofNat 32
                      (program.pe.imageBase + table.continuationRva)))
                  (nativeX87ReplayRetState input) := by
            calc
              _ = runKernelMixedReplaySemantic program.pe program.imports
                    undefinedSlot input [first.instruction] := by
                  simpa [entriesExact] using concreteExact
              _ = runNativeX87ReplayTemplateRoles program.pe program.imports
                    undefinedSlot input
                    (nativeX87ReplayFixedTemplateReturnRoles
                      runtimeTarget.target.frameMapping) := by
                  simpa [entriesExact] using semanticExact
              _ = .stopped
                    (.returned (Memory.read32 input.memory input.registers.esp))
                    (nativeX87ReplayRetState input) := semanticStopped
              _ = .stopped
                    (.returned
                      (BitVec.ofNat 32
                        (program.pe.imageBase + table.continuationRva)))
                    (nativeX87ReplayRetState input) := by
                  rw [returnAddressExact]
          have worldStopped :=
            runRelatedSteps_mixedReplay_return program first.instruction
              undefinedSlot input (nativeX87ReplayRetState input)
              { continuationRva := table.continuationRva,
                returnAddress := BitVec.ofNat 32
                  (program.pe.imageBase + table.continuationRva) }
              calls 0 [] RelationalWorld.empty [] concreteStopped
          have oneFuel : static.schedule.returnFuel = 1 := by
            rw [static.returnFuelExact, phaseLength]
            rfl
          have firstRva :
              first.instruction.rva =
                runtimeTarget.target.frameMapping.returnRva := by
            have roleHead :=
              kernelMixedReplayTemplateRoles?_head_rva first []
                (.ordinary runtimeTarget.target.frameMapping.returnRva .ret 1)
                []
                (by
                  simpa [entriesExact,
                    nativeX87ReplayFixedTemplateReturnRoles] using rolesExact)
            simpa [NativeX87ReplayTemplateRole.rva] using roleHead
          rw [oneFuel, ← firstRva, worldStopped]
      | cons second rest =>
          have impossible : False := by
            have lengthExact := phaseLength
            simp [entriesExact,
              nativeX87ReplayFixedTemplateReturnRoles] at lengthExact
          exact impossible.elim

private theorem exactNativeX87ReplayFixedTemplateReturnEndpoint_isSome
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programPe : program.pe = pe) (programImports : program.imports = imports)
    (undefinedSlot : Nat) (input : MachineState)
    (returnAddressExact :
      Memory.read32 input.memory input.registers.esp =
        BitVec.ofNat 32 (program.pe.imageBase + table.continuationRva))
    (calls : List NativeCallFrame) :
    (exactNativeX87ReplaySilentRunningEndpoint?
      (runRelatedSteps program.transitionSystem static.schedule.returnFuel
        (.running runtimeTarget.target.frameMapping.returnRva undefinedSlot
          input
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          0 [] RelationalWorld.empty []))
      table.continuationRva 0 calls).isSome = true := by
  rw [exactNativeX87ReplayFixedTemplateReturnRun runtimeTarget static program
    programPe programImports undefinedSlot input returnAddressExact calls]
  simp [exactNativeX87ReplaySilentRunningEndpoint?]

/-- A checked `some` result packages the computed value and its exact equation,
so dependent certificate fields consume an opaque fact rather than binding an
equation in every nested match. -/
structure ExactOptionValue (result : Option α) where
  value : α
  exact : result = some value

def exactOptionValue? (result : Option α) :
    Option (ExactOptionValue result) :=
  match result with
  | none => none
  | some value => some { value, exact := rfl }

theorem exactOptionValue_eq_some_of_eq
    {result : Option α} (value : α) (exact : result = some value) :
    exactOptionValue? result =
      some ({ value, exact } : ExactOptionValue result) := by
  subst result
  simp [exactOptionValue?]

/-- Execute the complete fixed bridge in a canonical empty nested-world
envelope.  All values and equations in the resulting certificate are produced
by exact decoders and transition functions; `none` is the only result for an
unsupported x87 command, faulting state, malformed schedule, unexpected
control path, observation, or post-frame mismatch. -/
def exactNativeX87ReplayFixedTemplateCertificate?
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    Option (ExactNativeX87ReplayFixedTemplateCertificate runtimeTarget program
      originalPe caller logicalInput source) :=
  match exactOptionValue?
      (nativeX87ReplayFixedTemplateExecutionSchedule?
        runtimeTarget.target.frameMapping) with
  | none => none
  | some scheduleExecution =>
      let schedule := scheduleExecution.value
      match exactOptionValue?
          (executeX87Singleton originalPe
            (replayInstructionRecord runtimeTarget.target.descriptor.replay)
            logicalInput) with
      | none => none
      | some originalExecution =>
              let result := originalExecution.value
              let returnFrame : NativeCallFrame := {
                continuationRva := table.continuationRva
                returnAddress := BitVec.ofNat 32
                  (program.pe.imageBase + table.continuationRva)
              }
              let bridgeCalls := [returnFrame]
              let callResult := runRelatedSteps program.transitionSystem 1
                (.running table.callInstruction.rva 0 caller [] 0 []
                  RelationalWorld.empty [])
              match exactNativeX87ReplaySilentRunningEndpoint? callResult
                    runtimeTarget.target.descriptor.bridge.entry.rva
                    0
                    bridgeCalls with
              | none => none
              | some callEndpoint =>
                  let entryResult := runRelatedSteps program.transitionSystem
                    schedule.entryFuel
                    (.running runtimeTarget.target.descriptor.bridge.entry.rva 0
                      callEndpoint.state bridgeCalls 0 [] RelationalWorld.empty [])
                  match exactNativeX87ReplaySilentRunningEndpoint? entryResult
                        runtimeTarget.target.frameMapping.instructionRva
                        schedule.entryFuel
                        bridgeCalls with
                  | none => none
                  | some entryEndpoint =>
                      if instructionPhysicalInput :
                          entryEndpoint.state.x87Physical =
                            source.candidateInput.x87Physical then
                        if instructionCommandInput :
                            StageA.Relational.X87.commandStepInput pe
                                runtimeTarget.addressMap.candidateInstructionRva
                                source.commandInput.candidateDescriptor
                                entryEndpoint.state =
                              StageA.Relational.X87.commandStepInput pe
                                runtimeTarget.addressMap.candidateInstructionRva
                                source.commandInput.candidateDescriptor
                                source.candidateInput then
                          match exactOptionValue?
                              (executeX87Singleton pe
                                (replayInstructionRecordAt
                                  runtimeTarget.target.descriptor.replay
                                  runtimeTarget.addressMap.candidateInstructionRva)
                                entryEndpoint.state) with
                          | none => none
                          | some candidateExecution =>
                            let candidateResult := candidateExecution.value
                            let instructionResult :=
                              runRelatedSteps program.transitionSystem
                                schedule.instructionFuel
                                (.running
                                  runtimeTarget.target.frameMapping.instructionRva
                                  schedule.entryFuel entryEndpoint.state
                                  bridgeCalls 0 []
                                  RelationalWorld.empty [])
                            match exactNativeX87ReplaySilentRunningEndpoint?
                                  instructionResult
                                  runtimeTarget.target.frameMapping.captureRva
                                  (schedule.entryFuel + schedule.instructionFuel)
                                  bridgeCalls with
                            | none => none
                            | some instructionEndpoint =>
                                let captureResult :=
                                  runRelatedSteps program.transitionSystem
                                    schedule.captureFuel
                                    (.running
                                      runtimeTarget.target.frameMapping.captureRva
                                      (schedule.entryFuel +
                                        schedule.instructionFuel)
                                      instructionEndpoint.state bridgeCalls 0 []
                                      RelationalWorld.empty [])
                                match exactNativeX87ReplaySilentRunningEndpoint?
                                      captureResult
                                      runtimeTarget.target.frameMapping.returnRva
                                      (schedule.entryFuel +
                                        schedule.instructionFuel +
                                        schedule.captureFuel)
                                      bridgeCalls with
                                | none => none
                                | some captureEndpoint =>
                                  let returnResult :=
                                    runRelatedSteps program.transitionSystem
                                      schedule.returnFuel
                                      (.running
                                        runtimeTarget.target.frameMapping.returnRva
                                        (schedule.entryFuel +
                                          schedule.instructionFuel +
                                          schedule.captureFuel)
                                        captureEndpoint.state bridgeCalls 0 []
                                        RelationalWorld.empty [])
                                  match exactNativeX87ReplaySilentRunningEndpoint?
                                        returnResult table.continuationRva 0
                                        [] with
                                  | none => none
                                  | some returnEndpoint =>
                                    match exactNativeX87ReplayCheckedPostFrame?
                                          runtimeTarget source
                                          returnEndpoint.state result
                                          candidateResult with
                                    | none => none
                                    | some postFrame =>
                                      some {
                                        result
                                        candidateResult
                                        calleeEntry := callEndpoint.state
                                        instructionSlot := schedule.entryFuel
                                        instructionEntryState :=
                                          entryEndpoint.state
                                        originalExecuted :=
                                          originalExecution.exact
                                        candidateExecuted :=
                                          candidateExecution.exact
                                        instructionPhysicalInput
                                        instructionCommandInput
                                        captureSlot := schedule.entryFuel +
                                          schedule.instructionFuel
                                        captureEntryState :=
                                          instructionEndpoint.state
                                        returnSlot := schedule.entryFuel +
                                          schedule.instructionFuel +
                                          schedule.captureFuel
                                        returnEntryState :=
                                          captureEndpoint.state
                                        returned := returnEndpoint.state
                                        calls := []
                                        eventIndex := 0
                                        events := []
                                        world := RelationalWorld.empty
                                        externalFrames := []
                                        entryFuel := schedule.entryFuel
                                        entryFuelPositive :=
                                          schedule.entryFuelPositive
                                        instructionFuel :=
                                          schedule.instructionFuel
                                        instructionFuelPositive :=
                                          schedule.instructionFuelPositive
                                        captureFuel := schedule.captureFuel
                                        captureFuelPositive :=
                                          schedule.captureFuelPositive
                                        returnFuel := schedule.returnFuel
                                        returnFuelPositive :=
                                          schedule.returnFuelPositive
                                        callRun := by
                                          simpa [callResult, bridgeCalls,
                                            returnFrame] using callEndpoint.exact
                                        entryRun := by
                                          simpa [entryResult, bridgeCalls,
                                            returnFrame] using entryEndpoint.exact
                                        instructionRun := by
                                          simpa [instructionResult, bridgeCalls,
                                            returnFrame] using
                                            instructionEndpoint.exact
                                        captureRun := by
                                          simpa [captureResult, bridgeCalls,
                                            returnFrame] using
                                            captureEndpoint.exact
                                        returnRun := by
                                          simpa [returnResult, bridgeCalls,
                                            returnFrame] using
                                            returnEndpoint.exact
                                        targetAfter := postFrame.targetAfter
                                        activeAfter := postFrame.activeAfter
                                        parentAfter := postFrame.parentAfter
                                        privateStackEstablished :=
                                          postFrame.privateStackEstablished
                                        statusSucceeded :=
                                          postFrame.statusSucceeded
                                        outputEncoded := postFrame.outputEncoded
                                        faultFree := postFrame.faultFree
                                        nonX87Output := postFrame.nonX87Output
                                        memoryEffects := postFrame.memoryEffects
                                        physicalState := postFrame.physicalState
                                      }
                        else none
                      else none

/-- Every statically checked fixed-template target executes successfully for
every admitted source frame.  This theorem composes exact singleton semantics,
opaque exact phase runs, and the checked post-frame result; it does not accept
target-indexed endpoint or status evidence. -/
theorem exactNativeX87ReplayFixedTemplateCertificate_isSome_of_static
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (static :
      ExactNativeX87ReplayFixedTemplateStaticExecution runtimeTarget)
    (program : ExactNestedNativeWorldProgram)
    (programBinding :
      ExactNativeX87ReplayKernelProgramBinding inventory program)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    (exactNativeX87ReplayFixedTemplateCertificate? runtimeTarget program
      originalPe caller logicalInput source).isSome = true := by
  have peExact := programBinding.peExact
  have importsExact := programBinding.importsExact
  subst pe
  subst imports
  have imageBounded := programBinding.imageBounded
  have originalSome :=
    exactNativeX87ReplayOriginalSingleton_isSome runtimeTarget originalPe caller
      logicalInput source
  cases originalExecuted :
      executeX87Singleton originalPe
        (replayInstructionRecord runtimeTarget.target.descriptor.replay)
        logicalInput with
  | none =>
      simp [originalExecuted] at originalSome
  | some originalResult =>
      let entryState :=
        nativeX87ReplayFixedTemplateInstructionEntryState table program.pe
          source.inputCandidate caller
      have instructionPhysicalInput :
          entryState.x87Physical = source.candidateInput.x87Physical := by
        exact
          (nativeX87ReplayFixedTemplateInstructionEntryState_x87Physical table
            program.pe source.inputCandidate caller).trans
            source.candidateX87.symm
      have instructionRegisters :
          entryState.registers = logicalInput.registers := by
        exact nativeX87ReplayFixedTemplateInstructionEntryState_registers
          runtimeTarget originalPe caller logicalInput source imageBounded
      have instructionEflags :
          entryState.eflags = logicalInput.eflags := by
        exact nativeX87ReplayFixedTemplateInstructionEntryState_eflags_exact
          runtimeTarget originalPe caller logicalInput source imageBounded
      have instructionSemantics :
          entryState.x87Semantics = source.candidateInput.x87Semantics := by
        exact nativeX87ReplayFixedTemplateInstructionEntryState_x87Semantics
          runtimeTarget originalPe caller logicalInput source
      have instructionCommandInput :
          StageA.Relational.X87.commandStepInput program.pe
              runtimeTarget.addressMap.candidateInstructionRva
              source.commandInput.candidateDescriptor entryState =
            StageA.Relational.X87.commandStepInput program.pe
              runtimeTarget.addressMap.candidateInstructionRva
              source.commandInput.candidateDescriptor source.candidateInput := by
        exact nativeX87ReplayFixedTemplateInstructionEntryState_commandInput
          runtimeTarget originalPe caller logicalInput source imageBounded
      have candidateSome := static.candidateSingleton_isSome entryState
      cases candidateExecuted :
          executeX87Singleton program.pe
            (replayInstructionRecordAt
              runtimeTarget.target.descriptor.replay
              runtimeTarget.addressMap.candidateInstructionRva)
            entryState with
      | none =>
          simp [candidateExecuted] at candidateSome
      | some candidateResult =>
          have postFacts :=
            exactNativeX87ReplaySingletonPostFacts runtimeTarget originalPe
              caller logicalInput entryState source instructionPhysicalInput
              instructionRegisters instructionEflags instructionCommandInput
              instructionSemantics originalResult candidateResult
              originalExecuted candidateExecuted
          let returnFrame : NativeCallFrame := {
            continuationRva := table.continuationRva
            returnAddress := BitVec.ofNat 32
              (program.pe.imageBase + table.continuationRva)
          }
          let bridgeCalls := [returnFrame]
          have callRun := exactNativeX87ReplayCallRun programBinding source
          have entryRun :=
            exactNativeX87ReplayFixedTemplateEntryRun runtimeTarget static
              inventory program programBinding originalPe caller logicalInput
              source bridgeCalls
          let captureInput :=
            nativeX87ReplayNopState
              (nativeX87ReplayFixedTemplateInstructionRegionSize -
                static.candidateDescriptor.size)
              candidateResult.state
          have instructionRun :=
            exactNativeX87ReplayFixedTemplateInstructionRun runtimeTarget static
              program rfl rfl static.schedule.entryFuel entryState
              candidateResult candidateExecuted postFacts.faultFree.2 bridgeCalls
          have captureActive :
              Memory.read32
                  (nativeX87ReplayPushRegState .eax
                    (nativeX87ReplayPushFlagsState captureInput)).memory
                  (BitVec.ofNat 32
                    ((program.pe.imageBase + table.activeFramePointerRva) %
                      (2 ^ 32))) =
                source.frameAddress := by
            simpa [captureInput, entryState] using
              nativeX87ReplayFixedTemplateCaptureBeforeSaveState_active
                runtimeTarget static originalPe caller logicalInput source
                imageBounded candidateResult candidateExecuted
          have captureRun :=
            exactNativeX87ReplayFixedTemplateCaptureRun runtimeTarget static
              program rfl rfl
              (static.schedule.entryFuel + static.schedule.instructionFuel)
              source.frameAddress captureInput captureActive
              source.outputX87FrameAddressValid bridgeCalls
          let finalState :=
            nativeX87ReplayFixedTemplateCaptureFinalState table program.pe
              (static.schedule.entryFuel + static.schedule.instructionFuel)
              source.frameAddress captureInput
          have returnAddressExact :
              Memory.read32 finalState.memory finalState.registers.esp =
                BitVec.ofNat 32
                  (program.pe.imageBase + table.continuationRva) := by
            simpa [finalState, captureInput, entryState] using
              nativeX87ReplayFixedTemplateCaptureFinalState_returnEndpoint
                runtimeTarget static originalPe caller logicalInput source
                imageBounded
                (static.schedule.entryFuel +
                  static.schedule.instructionFuel)
                candidateResult candidateExecuted
          have returnRun :=
            exactNativeX87ReplayFixedTemplateReturnRun runtimeTarget static
              program rfl rfl
              (static.schedule.entryFuel + static.schedule.instructionFuel +
                static.schedule.captureFuel)
              finalState returnAddressExact []
          have postFrameSome :=
            exactNativeX87ReplayCheckedPostFrame_returned_isSome runtimeTarget
              static originalPe caller logicalInput source imageBounded
              (static.schedule.entryFuel + static.schedule.instructionFuel)
              originalResult candidateResult originalExecuted candidateExecuted
              postFacts
          cases postFrameExact :
              exactNativeX87ReplayCheckedPostFrame? runtimeTarget source
                (nativeX87ReplayRetState finalState) originalResult
                candidateResult with
          | none =>
              simp [finalState, captureInput, postFrameExact] at postFrameSome
          | some postFrame =>
              have callEndpointExact :=
                exactNativeX87ReplaySilentRunningEndpoint_eq_some_of_run
                  (indirectCallEntryState
                    (program.pe.imageBase + table.continuationRva) caller)
                  callRun
              have entryEndpointExact :=
                exactNativeX87ReplaySilentRunningEndpoint_eq_some_of_run
                  entryState entryRun
              have instructionEndpointExact :=
                exactNativeX87ReplaySilentRunningEndpoint_eq_some_of_run
                  captureInput instructionRun
              have captureEndpointExact :=
                exactNativeX87ReplaySilentRunningEndpoint_eq_some_of_run
                  finalState captureRun
              have returnEndpointExact :=
                exactNativeX87ReplaySilentRunningEndpoint_eq_some_of_run
                  (nativeX87ReplayRetState finalState) returnRun
              have scheduleExecutionExact :=
                exactOptionValue_eq_some_of_eq static.schedule
                  static.scheduleExact
              have originalExecutionExact :=
                exactOptionValue_eq_some_of_eq originalResult originalExecuted
              have candidateExecutionExact :=
                exactOptionValue_eq_some_of_eq candidateResult candidateExecuted
              simp only [exactNativeX87ReplayFixedTemplateCertificate?,
                returnFrame, bridgeCalls, entryState, captureInput, finalState,
                scheduleExecutionExact, originalExecutionExact,
                callEndpointExact,
                ExactNativeX87ReplaySilentRunningEndpoint.ofRun,
                entryEndpointExact,
                dif_pos instructionPhysicalInput,
                dif_pos instructionCommandInput, candidateExecutionExact,
                instructionEndpointExact, captureEndpointExact,
                returnEndpointExact, postFrameExact, Option.isSome_some]

/-- Inventory-level universal closure.  Generated code supplies only the
state-independent checked static inventory; dynamic execution success follows
for every member and admitted source frame. -/
theorem exactNativeX87ReplayFixedTemplateCertificate_isSome
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    (staticInventory :
      ExactNativeX87ReplayFixedTemplateStaticInventory inventory)
    (program : ExactNestedNativeWorldProgram)
    (programBinding :
      ExactNativeX87ReplayKernelProgramBinding inventory program)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (member : runtimeTarget ∈ inventory.targets)
    (originalPe : PE32) (caller logicalInput : MachineState)
    (source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput) :
    (exactNativeX87ReplayFixedTemplateCertificate? runtimeTarget program
      originalPe caller logicalInput source).isSome = true := by
  obtain ⟨static⟩ := staticInventory.forTarget runtimeTarget member
  exact exactNativeX87ReplayFixedTemplateCertificate_isSome_of_static
    runtimeTarget static program programBinding originalPe caller logicalInput
    source

private theorem exactSilentEndpoint
    {system : RelatedTransitionSystem state observation}
    {fuel : Nat} {before after : state}
    (exact : runRelatedSteps system fuel before = (after, [])) :
    (runRelatedSteps system fuel before).1 = after :=
  congrArg Prod.fst exact

private theorem exactSilentObservations
    {system : RelatedTransitionSystem state observation}
    {fuel : Nat} {before after : state}
    (exact : runRelatedSteps system fuel before = (after, [])) :
    (runRelatedSteps system fuel before).2 = [] :=
  congrArg Prod.snd exact

structure X87SingletonNonPhysicalPreserved
    (input : MachineState) (result : StepResult) : Prop where
  undefinedValue : result.state.undefinedValue = input.undefinedValue
  legacyX87 : result.state.x87 = input.x87
  semantics : result.state.x87Semantics = input.x87Semantics
  fsBase : result.state.fsBase = input.fsBase

theorem executeX87Singleton_nonPhysicalPreserved
    (pe : PE32) (record : RawInstructionRecord)
    (input : MachineState) (result : StepResult)
    (executed : executeX87Singleton pe record input = some result) :
    X87SingletonNonPhysicalPreserved input result := by
  let witness := executeX87Singleton_witness pe record input result executed
  refine {
    undefinedValue := ?_
    legacyX87 := ?_
    semantics := ?_
    fsBase := ?_
  } <;>
    rw [witness.resultState] <;>
    simp [RelationalBehavior.nextMachineState, witness.effectBound]

/-- Construct the reduction value once the generic proof premises are
available.  The public theorem below packages this value as the proposition
consumed by the runtime kernel interface. -/
private def executeKernelReductionValue
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32}
    {handler : CandidateReplayHandler}
    {caller logicalInput : MachineState}
    {source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput}
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (handlerInventory : ExactNativeX87ReplayHandlerInventoryCorrespondence
      inventory originalPe handler)
    (member : runtimeTarget ∈ inventory.targets)
    (certificate : ExactNativeX87ReplayFixedTemplateCertificate
      runtimeTarget program originalPe caller logicalInput source) :
    ExactNativeX87ReplayBridgeKernelReduction
      runtimeTarget program handler caller logicalInput := by
  have peExact := programBinding.peExact
  subst pe
  have outputRelated :=
    nativeX87ReplayPhysicalStatesRelatedChecked_sound
      runtimeTarget.addressMap certificate.result.state.x87Physical
      certificate.candidateResult.state.x87Physical certificate.physicalState
  have originalPreserved := executeX87Singleton_nonPhysicalPreserved
    originalPe
    (replayInstructionRecord runtimeTarget.target.descriptor.replay)
    logicalInput certificate.result certificate.originalExecuted
  have candidatePreserved := executeX87Singleton_nonPhysicalPreserved
    program.pe
    (replayInstructionRecordAt runtimeTarget.target.descriptor.replay
      runtimeTarget.addressMap.candidateInstructionRva)
    certificate.instructionEntryState certificate.candidateResult
    certificate.candidateExecuted
  have sharedSemantics :
      logicalInput.x87Semantics = caller.x87Semantics :=
    source.engineRelated.originalSemantics.trans source.callerSemantics.symm
  have handlerResult :
      handler runtimeTarget.target.descriptor.replay logicalInput =
        some certificate.result := by
    calc
      handler runtimeTarget.target.descriptor.replay logicalInput =
          executeX87Singleton originalPe
            (replayInstructionRecord runtimeTarget.target.descriptor.replay)
            logicalInput :=
        handlerInventory.execute runtimeTarget member logicalInput
      _ = some certificate.result := certificate.originalExecuted
  let call : ExactComputedNestedNativeWorldSegment program
      (.running table.callInstruction.rva 0 caller certificate.calls
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := 1
    positive := Nat.zero_lt_succ 0
  }
  let entry : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.descriptor.bridge.entry.rva 0
        certificate.calleeEntry
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.entryFuel
    positive := certificate.entryFuelPositive
  }
  let instruction : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.frameMapping.instructionRva
        certificate.instructionSlot
        certificate.instructionEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.instructionFuel
    positive := certificate.instructionFuelPositive
  }
  let capture : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.frameMapping.captureRva
        certificate.captureSlot
        certificate.captureEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.captureFuel
    positive := certificate.captureFuelPositive
  }
  let returnSegment : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.frameMapping.returnRva
        certificate.returnSlot
        certificate.returnEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.returnFuel
    positive := certificate.returnFuelPositive
  }
  exact {
    originalPe
    result := certificate.result
    handlerResult
    calleeEntry := certificate.calleeEntry
    instructionSlot := certificate.instructionSlot
    instructionEntryState := certificate.instructionEntryState
    captureSlot := certificate.captureSlot
    captureEntryState := certificate.captureEntryState
    returnSlot := certificate.returnSlot
    returnEntryState := certificate.returnEntryState
    returned := certificate.returned
    calls := certificate.calls
    eventIndex := certificate.eventIndex
    events := certificate.events
    world := certificate.world
    externalFrames := certificate.externalFrames
    sourceFrame := source
    call
    callOne := rfl
    callAtTarget := by
      simpa [call, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.callRun
    callSilent := by
      simpa [call, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.callRun
    entry
    entryAtInstruction := by
      simpa [entry, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.entryRun
    entrySilent := by
      simpa [entry, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.entryRun
    instruction
    instructionAtCapture := by
      simpa [instruction, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.instructionRun
    instructionSilent := by
      simpa [instruction, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.instructionRun
    capture
    captureAtReturn := by
      simpa [capture, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.captureRun
    captureSilent := by
      simpa [capture, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.captureRun
    returnSegment
    returnedAtContinuation := by
      simpa [returnSegment, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.returnRun
    returnSilent := by
      simpa [returnSegment, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.returnRun
    frameEffect := {
      source := source.toNativeX87ReplayBridgeSourceFrameEvidence
      targetAfter := certificate.targetAfter
      activeAfter := certificate.activeAfter
      parentAfter := certificate.parentAfter
      privateStackEstablished := certificate.privateStackEstablished
      statusSucceeded := certificate.statusSucceeded
      outputCandidate := certificate.candidateResult.state.x87Physical
      outputFrame := {
        encoded := certificate.outputEncoded
        related := outputRelated
      }
      mixedPost := {
        source := source.toNativeX87ReplayBridgeSourceFrameEvidence
        candidateExecutionInput := certificate.instructionEntryState
        candidateResult := certificate.candidateResult
        candidatePhysicalInput := certificate.instructionPhysicalInput
        candidateCommandInput := certificate.instructionCommandInput
        layoutCompatible := source.layoutCompatible
        outputEngineBase := source.engineBase
        architecturalMemoryUnmapped := source.memoryUnmapped
        faultFree := certificate.faultFree
        nonX87Output := certificate.nonX87Output
        memoryEffects := certificate.memoryEffects
        physicalState := certificate.physicalState
        logicalUndefinedValue := originalPreserved.undefinedValue
        candidateUndefinedValue := candidatePreserved.undefinedValue
        logicalLegacyX87 := originalPreserved.legacyX87
        candidateLegacyX87 := candidatePreserved.legacyX87
        logicalSemantics := originalPreserved.semantics
        candidateSemantics := candidatePreserved.semantics
        sharedSemantics
        logicalFsBase := originalPreserved.fsBase
        candidateFsBase := candidatePreserved.fsBase
        outputFrame := {
          encoded := certificate.outputEncoded
          related := outputRelated
        }
      }
    }
  }

/-- Universal fixed-template proof for any member of the checked runtime
inventory.  The remaining certificate premises are all semantic equations or
explicit frame facts; no target-specific theorem body is generated. -/
theorem executeKernelReduction
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32}
    {handler : CandidateReplayHandler}
    {caller logicalInput : MachineState}
    {source : ExactNativeX87ReplaySourceFrame runtimeTarget originalPe
      caller logicalInput}
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (handlerInventory : ExactNativeX87ReplayHandlerInventoryCorrespondence
      inventory originalPe handler)
    (member : runtimeTarget ∈ inventory.targets)
    (certificate : ExactNativeX87ReplayFixedTemplateCertificate
      runtimeTarget program originalPe caller logicalInput source) :
    Nonempty (ExactNativeX87ReplayBridgeKernelReduction
      runtimeTarget program handler caller logicalInput) :=
  ⟨executeKernelReductionValue programBinding handlerInventory member certificate⟩

/-! The fixed-template executor contains only state-independent checked static
decode/shape evidence.  Program/handler bindings and every dynamic singleton,
phase, and frame equation are constructed and universally proved by the kernel. -/
structure ExactNativeX87ReplayFixedTemplateExecutor
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (originalPe : PE32) : Prop where
  staticInventory :
    ExactNativeX87ReplayFixedTemplateStaticInventory inventory

/-- Generic construction of the runtime kernel execution goal. -/
theorem ExactNativeX87ReplayFixedTemplateExecutor.kernelExecution
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32}
    {handler : CandidateReplayHandler}
    (executor : ExactNativeX87ReplayFixedTemplateExecutor
      inventory program originalPe)
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (handlerInventory : ExactNativeX87ReplayHandlerInventoryCorrespondence
      inventory originalPe handler) :
    ExactNativeX87ReplayBridgeKernelExecution
      inventory program originalPe handler := by
  refine { reduce := ?_ }
  intro runtimeTarget member caller logicalInput source
  have checked :=
    exactNativeX87ReplayFixedTemplateCertificate_isSome
      executor.staticInventory program programBinding runtimeTarget member
      originalPe caller logicalInput source
  cases certificateExact :
      exactNativeX87ReplayFixedTemplateCertificate? runtimeTarget program
        originalPe caller logicalInput source with
  | none => simp [certificateExact] at checked
  | some certificate =>
      exact executeKernelReduction programBinding handlerInventory member
        certificate

/-- Add the already-derived structural and semantic bindings around the sole
dynamic executor to obtain the complete fixed-template interface. -/
theorem ExactNativeX87ReplayFixedTemplateExecutor.templateExecution
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {originalPe : PE32}
    {handler : CandidateReplayHandler}
    (executor : ExactNativeX87ReplayFixedTemplateExecutor
      inventory program originalPe)
    (programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program)
    (handlerInventory : ExactNativeX87ReplayHandlerInventoryCorrespondence
      inventory originalPe handler) :
    ExactNativeX87ReplayTemplateExecution
      inventory program originalPe handler := {
  programPeExact := programBinding.peExact
  programImportsExact := programBinding.importsExact
  targetInventory := programBinding.targetInventory
  handlerInventory
  kernelExecution := executor.kernelExecution programBinding handlerInventory
}

#print axioms executeKernelReduction
#print axioms exactNativeX87ReplayFixedTemplateSchedule_isSome
#print axioms exactNativeX87ReplayFixedTemplateMixedReplay_isSome
#print axioms exactNativeX87ReplayFixedTemplateStaticExecutionOfIsSome
#print axioms KernelMixedReplayInstruction.semanticStep_running_slot
#print axioms runKernelMixedReplaySemantic_running_slot
#print axioms exactNativeX87ReplayOriginalSingleton_isSome
#print axioms exactNativeX87ReplayCandidateSingleton_isSome
#print axioms exactNativeX87ReplaySingletonPhysicalStatesChecked
#print axioms nativeX87ReplayEntrySavedState_returnAddress
#print axioms nativeX87ReplayPhysicalStatesRelatedChecked_sound
#print axioms executeX87Singleton_nonPhysicalPreserved
#print axioms exactNativeX87ReplayFixedTemplateCertificate?
#print axioms exactNativeX87ReplayFixedTemplateCertificate_isSome
#print axioms bindExactNativeX87ReplayNestedProgram_targetInventory
#print axioms exactNativeX87ReplayKernelProgramBinding
#print axioms ExactNativeX87ReplayFixedTemplateExecutor.kernelExecution
#print axioms ExactNativeX87ReplayFixedTemplateExecutor.templateExecution

end StageA.Relational.InterpreterKernelX87Execution
