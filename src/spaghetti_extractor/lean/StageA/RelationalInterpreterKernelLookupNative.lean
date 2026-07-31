import StageA.RelationalInterpreterKernelLookupABI
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelLookupNative

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelLookupABI
open StageA.Relational.InterpreterKernelLoop
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.InterpreterNativeWorld

/-!
The reflected summary deliberately stops before `NativeDispatches`.  This file
states the missing bridge against the real exact-instruction executor.  The
finite checker is generic in all RVAs.  The remaining semantic interface is
split into bounded local chunks; it cannot contain a caller-selected complete
path, simulation relation, or final postcondition.
-/

inductive ProgramLookupNativeBlockEffect where
  | enterFrame
  | compareRecord
  | advanceLow
  | lowerHigh
  | testInterval
  | testCount
  | testMatch
  | selectHit
  | selectMiss
  | leaveZeroEdxReturn
deriving Repr, DecidableEq

/-- Reflected native facts not represented by a plain CFG: frame bytes written
and EFLAGS bits read/written.  Bits are Intel CF=0, PF=2, AF=4, ZF=6, SF=7,
OF=11. -/
structure ProgramLookupNativeBlockShape where
  control : ProgramLookupRelativeBlockShape
  effect : ProgramLookupNativeBlockEffect
  frameWriteOffsets : List Nat
  flagReadBits : List Nat
  flagWriteBits : List Nat
deriving Repr, DecidableEq

def arithmeticFlagBits : List Nat := [0, 2, 4, 6, 7, 11]

private def defaultProgramLookupRelativeBlockShape :
    ProgramLookupRelativeBlockShape := {
  entryOffset := 0
  successorOffsets := []
  instructionOffsets := []
}

private instance : Inhabited ProgramLookupRelativeBlockShape :=
  ⟨defaultProgramLookupRelativeBlockShape⟩

def programLookupNativeBlockShapes : List ProgramLookupNativeBlockShape := [
  { control := programLookupTemplateBlockShapes[0]!
    effect := .enterFrame
    frameWriteOffsets := [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
    flagReadBits := []
    flagWriteBits := [] },
  { control := programLookupTemplateBlockShapes[1]!
    effect := .compareRecord
    frameWriteOffsets := [0, 1, 2, 3, 4, 5, 6, 7]
    flagReadBits := [0]
    flagWriteBits := arithmeticFlagBits },
  { control := programLookupTemplateBlockShapes[2]!
    effect := .advanceLow
    frameWriteOffsets := [12, 13, 14, 15]
    flagReadBits := []
    flagWriteBits := arithmeticFlagBits },
  { control := programLookupTemplateBlockShapes[3]!
    effect := .lowerHigh
    frameWriteOffsets := [8, 9, 10, 11]
    flagReadBits := []
    flagWriteBits := [] },
  { control := programLookupTemplateBlockShapes[4]!
    effect := .testInterval
    frameWriteOffsets := []
    flagReadBits := [0]
    flagWriteBits := arithmeticFlagBits },
  { control := programLookupTemplateBlockShapes[5]!
    effect := .testCount
    frameWriteOffsets := []
    flagReadBits := [0]
    flagWriteBits := arithmeticFlagBits },
  { control := programLookupTemplateBlockShapes[6]!
    effect := .testMatch
    frameWriteOffsets := []
    flagReadBits := [6]
    flagWriteBits := arithmeticFlagBits },
  { control := programLookupTemplateBlockShapes[7]!
    effect := .selectHit
    frameWriteOffsets := []
    flagReadBits := []
    flagWriteBits := arithmeticFlagBits },
  { control := programLookupTemplateBlockShapes[8]!
    effect := .selectMiss
    frameWriteOffsets := []
    flagReadBits := []
    flagWriteBits := [] },
  { control := programLookupTemplateBlockShapes[9]!
    effect := .leaveZeroEdxReturn
    frameWriteOffsets := []
    flagReadBits := []
    flagWriteBits := arithmeticFlagBits }
]

/-- Exact finite native-template check.  `programLookupTemplateChecked` fixes
all 161 bytes and decoder boundaries; this second reflected list records the
native stack/flag effect assigned to each exact block. -/
def programLookupNativeTemplateChecked (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (function : KernelFunction)
    (parameters : ProgramLookupTemplateParameters) : Bool :=
  programLookupTemplateChecked program pe imports function parameters &&
    function.blocks.length == programLookupNativeBlockShapes.length &&
    (List.zip programLookupNativeBlockShapes function.blocks).all
      (fun pair => pair.1.control.matches parameters.entryRva pair.2) &&
    decide (parameters.entryRva + 161 <= 2 ^ 32)

structure ProgramLookupNativeTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  template : ProgramLookupTemplateCertificate program pe imports function
  nativeChecked : programLookupNativeTemplateChecked program pe imports function
    template.parameters = true

theorem ProgramLookupTemplateParameters.ext
    {left right : ProgramLookupTemplateParameters}
    (entryRva : left.entryRva = right.entryRva)
    (tableRva : left.tableRva = right.tableRva)
    (countRva : left.countRva = right.countRva) : left = right := by
  cases left
  cases right
  simp_all

theorem ProgramLookupTemplateCertificate.entryRva_eq_functionStart
    (certificate : ProgramLookupTemplateCertificate program pe imports function) :
    certificate.parameters.entryRva = function.span.start := by
  have checked := certificate.checked
  simp only [programLookupTemplateChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.1.1.1.1.1.1.1.1.1.1.1.1.2.symm

/-- Attach the finite native effect checker to an already reflected 161-byte
template.  The additional argument is only a Boolean equality over the exact
function and PE; it contains no execution, path, or final-state evidence. -/
def programLookupTemplateCertificateToNative
    (certificate : ProgramLookupTemplateCertificate program pe imports function)
    (nativeChecked : programLookupNativeTemplateChecked program pe imports
      function certificate.parameters = true) :
    ProgramLookupNativeTemplateCertificate program pe imports function := {
  template := certificate
  nativeChecked
}

theorem ProgramLookupNativeTemplateCertificate.entryEndBounded
    (certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function) :
    certificate.template.parameters.entryRva + 161 <= 2 ^ 32 := by
  have checked := certificate.nativeChecked
  simp only [programLookupNativeTemplateChecked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  exact checked.2

class ProgramLookupNativeAddressBounds
    (parameters : ProgramLookupTemplateParameters) : Prop where
  entryEndBounded : parameters.entryRva + 161 <= 2 ^ 32

theorem programLookupRelativeTarget8Forward
    (parameters : ProgramLookupTemplateParameters)
    [bounds : ProgramLookupNativeAddressBounds parameters]
    (nextOffset byte targetOffset : Nat)
    (byteSmall : byte < 128)
    (targetExact : targetOffset = nextOffset + byte)
    (targetWithin : targetOffset < 161) :
    relativeTarget8 (parameters.entryRva + nextOffset) byte =
      parameters.entryRva + targetOffset := by
  unfold relativeTarget8 signExtendImmediate8
  rw [if_pos byteSmall, Nat.mod_eq_of_lt]
  · omega
  · have bounded := bounds.entryEndBounded
    omega

theorem programLookupRelativeTarget8Backward
    (parameters : ProgramLookupTemplateParameters)
    [bounds : ProgramLookupNativeAddressBounds parameters]
    (nextOffset byte targetOffset : Nat)
    (byteLarge : 128 <= byte)
    (byteBounded : byte <= 256)
    (targetExact : targetOffset + (256 - byte) = nextOffset)
    (targetWithin : targetOffset < 161) :
    relativeTarget8 (parameters.entryRva + nextOffset) byte =
      parameters.entryRva + targetOffset := by
  unfold relativeTarget8 signExtendImmediate8
  rw [if_neg (Nat.not_lt_of_ge byteLarge)]
  have sumExact :
      parameters.entryRva + nextOffset + (2 ^ 32 - (256 - byte)) =
        2 ^ 32 + (parameters.entryRva + targetOffset) := by
    omega
  rw [sumExact, Nat.add_mod, Nat.mod_self, Nat.zero_add, Nat.mod_mod,
    Nat.mod_eq_of_lt (by
      have bounded := bounds.entryEndBounded
      omega)]

/-- Deterministic execution of exactly `fuel` instructions in the real native
executor.  Terminal states remain terminal, matching `stepNativeExecution`. -/
def runProgramLookupNativeFuel (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) : Nat -> NativeExecution -> NativeExecution
  | 0, execution => execution
  | fuel + 1, execution =>
      runProgramLookupNativeFuel pe imports environment fuel
        (stepNativeExecution pe imports environment execution)

theorem runProgramLookupNativeFuel_stepsN (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (fuel : Nat) (before : NativeExecution) :
    NativeStepsN pe imports environment fuel before
      (runProgramLookupNativeFuel pe imports environment fuel before) := by
  induction fuel generalizing before with
  | zero => exact .zero before
  | succ fuel induction =>
      exact .succ fuel before
        (stepNativeExecution pe imports environment before)
        (runProgramLookupNativeFuel pe imports environment fuel
          (stepNativeExecution pe imports environment before)) rfl
        (induction (stepNativeExecution pe imports environment before))

theorem runProgramLookupNativeFuel_steps (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (fuel : Nat) (before : NativeExecution) :
    NativeSteps pe imports environment before
      (runProgramLookupNativeFuel pe imports environment fuel before) :=
  (runProgramLookupNativeFuel_stepsN pe imports environment fuel before).toNativeSteps

theorem runProgramLookupNativeFuel_add (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (first second : Nat) (before : NativeExecution) :
    runProgramLookupNativeFuel pe imports environment (first + second) before =
      runProgramLookupNativeFuel pe imports environment second
        (runProgramLookupNativeFuel pe imports environment first before) := by
  induction first generalizing before with
  | zero => simp [runProgramLookupNativeFuel]
  | succ first induction =>
      simp only [Nat.succ_add, runProgramLookupNativeFuel]
      exact induction (stepNativeExecution pe imports environment before)

/-- The world runner is the actual exact native-world transition system.  This
theorem constructs its path to the computed state and observations; identifying
that computed state with the ABI return remains an instruction-local bridge. -/
theorem runProgramLookupNativeWorldFuel_path
    (program : ExactNativeWorldProgram) (fuel : Nat)
    (before : NativeWorldExecution) :
    NonemptyRelatedPath program.transitionSystem before
      (runRelatedSteps program.transitionSystem (fuel + 1) before).2
      (runRelatedSteps program.transitionSystem (fuel + 1) before).1 := by
  exact ⟨fuel + 1, Nat.zero_lt_succ fuel, rfl⟩

def programLookupStackSub (stackPointer : Word) (bytes : Nat) : Word :=
  stackPointer + BitVec.ofNat 32 (2 ^ 32 - bytes)

theorem programLookupMidpointWord (low high midpoint : Nat)
    (ordered : low <= high) (highFits : high < 2 ^ 32)
    (midpointExact : midpoint = low + (high - low) / 2) :
    (BitVec.ofNat 32 low +
        ((BitVec.ofNat 32 high - BitVec.ofNat 32 low) >>> 1)) =
      BitVec.ofNat 32 midpoint := by
  apply BitVec.eq_of_toNat_eq
  have lowFits : low < 2 ^ 32 := Nat.lt_of_le_of_lt ordered highFits
  have wordsOrdered : BitVec.ofNat 32 low <= BitVec.ofNat 32 high := by
    simp only [BitVec.le_def, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt lowFits, Nat.mod_eq_of_lt highFits]
    exact ordered
  simp only [BitVec.toNat_add, BitVec.toNat_ushiftRight,
    BitVec.toNat_sub_of_le wordsOrdered, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt lowFits, Nat.mod_eq_of_lt highFits,
    Nat.shiftRight_eq_div_pow]
  rw [show 2 ^ 1 = 2 by rfl, midpointExact]

theorem programLookupTableAddressWord (pe : PE32) (tableRva index : Nat) :
    (((BitVec.ofNat 32 index <<< 2) + BitVec.ofNat 32 index) <<< 3) +
        BitVec.ofNat 32 (pe.imageBase + tableRva) =
      programLookupTableAddress pe tableRva index := by
  unfold programLookupTableAddress
  rw [BitVec.shiftLeft_eq_mul_twoPow, BitVec.shiftLeft_eq_mul_twoPow]
  simp [BitVec.twoPow, transferRecordSize, ← BitVec.ofNat_add,
    ← BitVec.ofNat_mul]
  congr 1
  omega

@[simp] theorem evalInputRegAddNormalizedConstant
    (state : MachineState) (reg : Reg) (value : Nat) :
    Expr.eval state ((Expr.inputReg reg).addNormalized (.constant value)) =
      state.registers.get reg + BitVec.ofNat 32 value := by
  cases value <;> simp [Expr.addNormalized, Expr.eval, Registers.get]

def programLookupRecordSlot (stackPointer : Word) : Word :=
  programLookupFrameByte stackPointer 0

def programLookupMidpointSlot (stackPointer : Word) : Word :=
  programLookupFrameByte stackPointer 4

def programLookupHighSlot (stackPointer : Word) : Word :=
  programLookupFrameByte stackPointer 8

def programLookupLowSlot (stackPointer : Word) : Word :=
  programLookupFrameByte stackPointer 12

def programLookupSavedEbpSlot (stackPointer : Word) : Word :=
  programLookupFrameByte stackPointer 16

def programLookupFlagIs (state : MachineState) (bit : Nat)
    (value : Bool) : Prop :=
  state.eflags.extractLsb' bit 1 = BitVec.ofNat 1 (if value then 1 else 0)

/-- Ordinary IA-32 instructions preserve the eight architecturally visible x87
stack slots.  The symbolic executor intentionally canonicalizes the total
`Nat -> X87Word` tail above slot seven, so whole-function equality of that
implementation function would be stronger than architectural preservation. -/
structure ProgramLookupArchitecturalX87Preserved
    (before after : MachineState) : Prop where
  stack : forall index, index < 8 -> after.x87.stack index = before.x87.stack index
  control : after.x87.control = before.x87.control
  status : after.x87.status = before.x87.status
  semantics : after.x87.semantics = before.x87.semantics

theorem ProgramLookupArchitecturalX87Preserved.trans
    (first : ProgramLookupArchitecturalX87Preserved before middle)
    (second : ProgramLookupArchitecturalX87Preserved middle after) :
    ProgramLookupArchitecturalX87Preserved before after := {
  stack := fun index inside => (second.stack index inside).trans
    (first.stack index inside)
  control := second.control.trans first.control
  status := second.status.trans first.status
  semantics := second.semantics.trans first.semantics
}

/-- State components untouched by every instruction in the reviewed lookup
template.  Keeping this as one reusable invariant prevents the loop and
epilogue cutpoints from accidentally forgetting a callee-save or machine
component required at the public ABI boundary. -/
structure ProgramLookupNativePreservedState
    (before state : MachineState) : Prop where
  ebx : state.registers.ebx = before.registers.ebx
  ecx : state.registers.ecx = before.registers.ecx
  esi : state.registers.esi = before.registers.esi
  edi : state.registers.edi = before.registers.edi
  directionFlag :
    state.eflags.extractLsb' 10 1 = before.eflags.extractLsb' 10 1
  undefinedValue : state.undefinedValue = before.undefinedValue
  x87 : ProgramLookupArchitecturalX87Preserved before state
  x87Physical : state.x87Physical = before.x87Physical
  x87Semantics : state.x87Semantics = before.x87Semantics
  fsBase : state.fsBase = before.fsBase

theorem ProgramLookupNativePreservedState.trans
    (first : ProgramLookupNativePreservedState before middle)
    (second : ProgramLookupNativePreservedState middle after) :
    ProgramLookupNativePreservedState before after := {
  ebx := second.ebx.trans first.ebx
  ecx := second.ecx.trans first.ecx
  esi := second.esi.trans first.esi
  edi := second.edi.trans first.edi
  directionFlag := second.directionFlag.trans first.directionFlag
  undefinedValue := second.undefinedValue.trans first.undefinedValue
  x87 := first.x87.trans second.x87
  x87Physical := second.x87Physical.trans first.x87Physical
  x87Semantics := second.x87Semantics.trans first.x87Semantics
  fsBase := second.fsBase.trans first.fsBase
}

structure ProgramLookupNativeLoopMachinePreserved
    (before after : MachineState) : Prop where
  esp : after.registers.esp = before.registers.esp
  ebp : after.registers.ebp = before.registers.ebp
  preserved : ProgramLookupNativePreservedState before after

theorem ProgramLookupNativeLoopMachinePreserved.trans
    (first : ProgramLookupNativeLoopMachinePreserved before middle)
    (second : ProgramLookupNativeLoopMachinePreserved middle after) :
    ProgramLookupNativeLoopMachinePreserved before after := {
  esp := second.esp.trans first.esp
  ebp := second.ebp.trans first.ebp
  preserved := first.preserved.trans second.preserved
}

def programLookupRecordSourcesFit
    (records : List StageA.Relational.Interpreter.ProgramRecord) : Bool :=
  records.all (fun record => record.sourceRva < 2 ^ 32)

theorem programLookupRecordSourcesFit_member
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (checked : programLookupRecordSourcesFit records = true)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (member : record ∈ records) : record.sourceRva < 2 ^ 32 := by
  simp only [programLookupRecordSourcesFit, List.all_eq_true] at checked
  simpa only [decide_eq_true_eq] using checked record member

theorem listAt?_mem {Value : Type} (values : List Value) (index : Nat)
    (value : Value) (found : listAt? values index = some value) : value ∈ values := by
  induction values generalizing index with
  | nil => simp [listAt?] at found
  | cons head tail induction =>
      cases index with
      | zero =>
          simp only [listAt?] at found
          cases found
          simp
      | succ index =>
          simp only [listAt?] at found
          exact List.mem_cons_of_mem head (induction index found)

theorem programLookupRecordSourcesFit_listAt
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (checked : programLookupRecordSourcesFit records = true)
    (index : Nat) (record : StageA.Relational.Interpreter.ProgramRecord)
    (found : listAt? records index = some record) : record.sourceRva < 2 ^ 32 :=
  programLookupRecordSourcesFit_member records checked record
    (listAt?_mem records index record found)

theorem listAt?_index_lt_length {Value : Type} (values : List Value) (index : Nat)
    (value : Value) (found : listAt? values index = some value) :
    index < values.length := by
  induction values generalizing index with
  | nil => simp [listAt?] at found
  | cons head tail induction =>
      cases index with
      | zero => simp
      | succ index =>
          simp only [listAt?] at found
          simpa using induction index found

theorem listAt?_none_length_le {Value : Type} (values : List Value) (index : Nat)
    (missing : listAt? values index = none) : values.length <= index := by
  induction values generalizing index with
  | nil => simp
  | cons head tail induction =>
      cases index with
      | zero => simp [listAt?] at missing
      | succ index =>
          simp only [listAt?] at missing
          simpa using induction index missing

theorem listAt?_exists_of_mem {Value : Type} (values : List Value) (value : Value)
    (member : value ∈ values) : exists index, listAt? values index = some value := by
  induction values with
  | nil => simp at member
  | cons head tail induction =>
      rcases List.mem_cons.mp member with rfl | inTail
      · exact ⟨0, rfl⟩
      · obtain ⟨index, found⟩ := induction inTail
        exact ⟨index + 1, by simpa [listAt?] using found⟩

theorem sourceRvasStrictlySorted_listAt_lt
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (sorted : sourceRvasStrictlySorted records)
    (leftIndex rightIndex : Nat)
    (left right : StageA.Relational.Interpreter.ProgramRecord)
    (leftAt : listAt? records leftIndex = some left)
    (rightAt : listAt? records rightIndex = some right)
    (before : leftIndex < rightIndex) : left.sourceRva < right.sourceRva := by
  induction records generalizing leftIndex rightIndex with
  | nil => simp [listAt?] at leftAt
  | cons head tail induction =>
      simp only [sourceRvasStrictlySorted, List.pairwise_cons] at sorted
      cases leftIndex with
      | zero =>
          simp only [listAt?] at leftAt
          cases leftAt
          cases rightIndex with
          | zero => omega
          | succ rightIndex =>
              simp only [listAt?] at rightAt
              exact sorted.1 right (listAt?_mem tail rightIndex right rightAt)
      | succ leftIndex =>
          cases rightIndex with
          | zero => omega
          | succ rightIndex =>
              simp only [listAt?] at leftAt rightAt
              exact induction (sorted := sorted.2) (leftIndex := leftIndex)
                (rightIndex := rightIndex) (leftAt := leftAt) (rightAt := rightAt)
                (before := by omega)

structure ProgramLookupLowerBound
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (sourceRva index : Nat) : Prop where
  within : index <= records.length
  before : forall query record,
    query < index -> listAt? records query = some record ->
      record.sourceRva < sourceRva
  atOrAfter : forall query record,
    index <= query -> listAt? records query = some record ->
      ¬ record.sourceRva < sourceRva

theorem reflectedProgramLookupTrace_lowerBoundWithin
    (trace : ReflectedProgramLookupTrace records sourceRva low high resultIndex)
    (sorted : sourceRvasStrictlySorted records)
    (beforeLow : forall query record,
      query < low -> listAt? records query = some record ->
        record.sourceRva < sourceRva)
    (afterHigh : forall query record,
      high <= query -> listAt? records query = some record ->
        ¬ record.sourceRva < sourceRva) :
    ProgramLookupLowerBound records sourceRva resultIndex := by
  induction trace with
  | done index invariant => exact ⟨invariant.2, beforeLow, afterHigh⟩
  | lower low high midpoint resultIndex record invariantBefore notConverged
      midpointExact recordAt recordLess invariantAfter rankDecreases rest induction =>
      apply induction
      · intro query queryRecord queryBefore queryAt
        by_cases belowLow : query < low
        · exact beforeLow query queryRecord belowLow queryAt
        · have queryLeMidpoint : query <= midpoint := by omega
          by_cases atMidpoint : query = midpoint
          · subst query
            cases (Option.some.inj (queryAt.symm.trans recordAt))
            exact recordLess
          · exact Nat.lt_trans
              (sourceRvasStrictlySorted_listAt_lt records sorted query midpoint
                queryRecord record queryAt recordAt (by omega)) recordLess
      · exact afterHigh
  | upper low high midpoint resultIndex record invariantBefore notConverged
      midpointExact recordAt recordNotLess invariantAfter rankDecreases rest induction =>
      apply induction
      · exact beforeLow
      · intro query queryRecord midpointBefore queryAt
        by_cases highBefore : high <= query
        · exact afterHigh query queryRecord highBefore queryAt
        · by_cases atMidpoint : query = midpoint
          · subst query
            cases (Option.some.inj (queryAt.symm.trans recordAt))
            exact recordNotLess
          · have midpointLtQuery : midpoint < query := by omega
            intro queryLess
            have recordLtQuery := sourceRvasStrictlySorted_listAt_lt records sorted
              midpoint query record queryRecord recordAt queryAt midpointLtQuery
            exact recordNotLess (Nat.lt_trans recordLtQuery queryLess)

theorem reflectedProgramLookupTrace_lowerBound
    (trace : ReflectedProgramLookupTrace records sourceRva 0 records.length
      resultIndex)
    (sorted : sourceRvasStrictlySorted records) :
    ProgramLookupLowerBound records sourceRva resultIndex := by
  apply reflectedProgramLookupTrace_lowerBoundWithin trace sorted
  · intro query record impossible
    omega
  · intro query record lengthBefore recordAt
    exact (Nat.not_lt_of_ge lengthBefore
      (listAt?_index_lt_length records query record recordAt)).elim

def indexedProgramRecordPointer
    (result : Option (Nat × StageA.Relational.Interpreter.ProgramRecord))
    (imageBase tableRva : Nat) : Word :=
  match result with
  | none => word32 0
  | some (index, _) =>
      word32 (imageBase + tableRva + index * transferRecordSize)

theorem programRecordPointer_suffix
    (leading trailing : List StageA.Relational.Interpreter.ProgramRecord)
    (imageBase tableRva sourceRva : Nat) :
    programRecordPointer (leading ++ trailing) imageBase tableRva sourceRva
        trailing.length =
      indexedProgramRecordPointer
        (lookupProgramRecordWithIndexAux trailing sourceRva leading.length)
        imageBase tableRva := by
  induction trailing generalizing leading with
  | nil => simp [programRecordPointer, lookupProgramRecordWithIndexAux,
      indexedProgramRecordPointer]
  | cons record tail induction =>
      by_cases same : (record.sourceRva == sourceRva) = true
      · simp [programRecordPointer, lookupProgramRecordWithIndexAux,
          indexedProgramRecordPointer, same]
      · rw [show leading ++ record :: tail = (leading ++ [record]) ++ tail by
          simp]
        simpa [programRecordPointer, lookupProgramRecordWithIndexAux,
          indexedProgramRecordPointer, same, List.length_append, Nat.add_assoc] using
          induction (leading ++ [record])

theorem lookupResultPointer_indexed
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (imageBase tableRva sourceRva : Nat) :
    lookupResultPointer records imageBase tableRva sourceRva =
      indexedProgramRecordPointer
        (lookupProgramRecordWithIndex? records sourceRva) imageBase tableRva := by
  simpa [lookupResultPointer, lookupProgramRecordWithIndex?] using
    programRecordPointer_suffix [] records imageBase tableRva sourceRva

theorem lookupProgramRecordWithIndexAux_at
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (sourceRva start index : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (recordAt : listAt? records index = some record)
    (recordExact : record.sourceRva = sourceRva)
    (before : forall query queryRecord,
      query < index -> listAt? records query = some queryRecord ->
        queryRecord.sourceRva < sourceRva) :
    lookupProgramRecordWithIndexAux records sourceRva start =
      some (start + index, record) := by
  induction records generalizing start index with
  | nil => simp [listAt?] at recordAt
  | cons head tail induction =>
      cases index with
      | zero =>
          simp only [listAt?] at recordAt
          cases recordAt
          simp [lookupProgramRecordWithIndexAux, recordExact]
      | succ index =>
          simp only [listAt?] at recordAt
          have headLess := before 0 head (by omega) rfl
          have headDifferent : (head.sourceRva == sourceRva) = false := by
            simp [beq_iff_eq, Nat.ne_of_lt headLess]
          rw [lookupProgramRecordWithIndexAux, if_neg (by simpa using headDifferent)]
          have tailBefore : forall query queryRecord,
              query < index -> listAt? tail query = some queryRecord ->
                queryRecord.sourceRva < sourceRva := by
            intro query queryRecord queryBefore queryAt
            exact before (query + 1) queryRecord (by omega) (by
              simpa [listAt?] using queryAt)
          simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
            induction (start := start + 1) (index := index)
              (recordAt := recordAt) tailBefore

theorem lookupProgramRecordWithIndexAux_none
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (sourceRva start : Nat)
    (different : forall record, record ∈ records -> record.sourceRva ≠ sourceRva) :
    lookupProgramRecordWithIndexAux records sourceRva start = none := by
  induction records generalizing start with
  | nil => rfl
  | cons head tail induction =>
      have headDifferent := different head (by simp)
      have tailDifferent : forall record, record ∈ tail ->
          record.sourceRva ≠ sourceRva := by
        intro record member
        exact different record (List.mem_cons_of_mem head member)
      simp [lookupProgramRecordWithIndexAux, beq_iff_eq, headDifferent,
        induction (start := start + 1) tailDifferent]

theorem ProgramLookupLowerBound.indexedResult
    (bound : ProgramLookupLowerBound records sourceRva index)
    (sorted : sourceRvasStrictlySorted records) :
    lookupProgramRecordWithIndex? records sourceRva =
      match listAt? records index with
      | some record =>
          if record.sourceRva = sourceRva then some (index, record) else none
      | none => none := by
  unfold lookupProgramRecordWithIndex?
  cases found : listAt? records index with
  | none =>
      apply lookupProgramRecordWithIndexAux_none
      intro record member same
      obtain ⟨query, queryAt⟩ := listAt?_exists_of_mem records record member
      have queryBeforeLength := listAt?_index_lt_length records query record queryAt
      have lengthBeforeIndex := listAt?_none_length_le records index found
      have queryBefore : query < index := by omega
      exact Nat.ne_of_lt (bound.before query record queryBefore queryAt) same
  | some record =>
      by_cases same : record.sourceRva = sourceRva
      · simp only [same, if_true]
        simpa using lookupProgramRecordWithIndexAux_at records sourceRva 0 index
          record found same bound.before
      · simp only [same, if_false]
        apply lookupProgramRecordWithIndexAux_none
        intro queryRecord member querySame
        obtain ⟨query, queryAt⟩ := listAt?_exists_of_mem records queryRecord member
        by_cases queryBefore : query < index
        · exact Nat.ne_of_lt (bound.before query queryRecord queryBefore queryAt)
            querySame
        · have indexBefore : index <= query := Nat.le_of_not_gt queryBefore
          by_cases atIndex : query = index
          · subst query
            cases (Option.some.inj (queryAt.symm.trans found))
            exact same querySame
          · have indexLtQuery : index < query := Nat.lt_of_le_of_ne indexBefore
              (Ne.symm atIndex)
            have recordLt := sourceRvasStrictlySorted_listAt_lt records sorted index
              query record queryRecord found queryAt indexLtQuery
            have sourceLtQuery : sourceRva < queryRecord.sourceRva := by
              have recordNotLess := bound.atOrAfter index record (Nat.le_refl _) found
              omega
            exact Nat.ne_of_gt sourceLtQuery querySame

theorem ProgramLookupLowerBound.returnWord
    (bound : ProgramLookupLowerBound records sourceRva index)
    (sorted : sourceRvasStrictlySorted records)
    (imageBase tableRva : Nat) :
    lookupResultPointer records imageBase tableRva sourceRva =
      match listAt? records index with
      | some record =>
          if record.sourceRva = sourceRva then
            word32 (imageBase + tableRva + index * transferRecordSize)
          else word32 0
      | none => word32 0 := by
  rw [lookupResultPointer_indexed, bound.indexedResult sorted]
  cases found : listAt? records index with
  | none => rfl
  | some record =>
      by_cases same : record.sourceRva = sourceRva <;>
        simp [indexedProgramRecordPointer, same]

/-! Candidate-specific generated code supplies only these finite decode facts.
The executor equation below is generic and reviewed: a certificate cannot
choose a successor state, path, branch result, or final response. -/

def programLookupNativeMemoryOperand (base : Option Reg)
    (displacement : Nat) : Operand32 :=
  .memory { base, index := none, scaleShift := 0, displacement }

def programLookupNativeEbpMemory (displacement : Nat) : Operand32 :=
  programLookupNativeMemoryOperand (some .ebp) displacement

/-- The reviewed instruction inventory of the 161-byte O0 template.  Absolute
data operands remain parameters; every opcode, width, displacement, and
instruction boundary is fixed. -/
def programLookupNativeExpectedInstruction? (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) :
    Nat -> Option (Instruction × Nat)
  | 0 => some (.pushReg .ebp, 1)
  | 1 => some (.movToOperand (.register .ebp) .esp, 2)
  | 3 => some (.binary .sub (.register .esp) (.immediate 16), 3)
  | 6 => some (.movImmediate
      (programLookupNativeEbpMemory (2 ^ 32 - 4)) 0, 7)
  | 13 => some (.movFromOperand .eax (programLookupNativeMemoryOperand none
      (pe.imageBase + parameters.countRva)), 5)
  | 18 => some (.movToOperand
      (programLookupNativeEbpMemory (2 ^ 32 - 8)) .eax, 3)
  | 21 => some (.jumpRel8 0x42, 2)
  | 23 => some (.movFromOperand .eax
      (programLookupNativeEbpMemory (2 ^ 32 - 8)), 3)
  | 26 => some (.binary .sub (.register .eax)
      (programLookupNativeEbpMemory (2 ^ 32 - 4)), 3)
  | 29 => some (.shift .right (.register .eax) (.immediate 1), 2)
  | 31 => some (.movToOperand (.register .edx) .eax, 2)
  | 33 => some (.movFromOperand .eax
      (programLookupNativeEbpMemory (2 ^ 32 - 4)), 3)
  | 36 => some (.binary .add (.register .eax) (.register .edx), 2)
  | 38 => some (.movToOperand
      (programLookupNativeEbpMemory (2 ^ 32 - 12)) .eax, 3)
  | 41 => some (.movFromOperand .edx
      (programLookupNativeEbpMemory (2 ^ 32 - 12)), 3)
  | 44 => some (.movToOperand (.register .eax) .edx, 2)
  | 46 => some (.shift .left (.register .eax) (.immediate 2), 3)
  | 49 => some (.binary .add (.register .eax) (.register .edx), 2)
  | 51 => some (.shift .left (.register .eax) (.immediate 3), 3)
  | 54 => some (.binary .add (.register .eax)
      (.immediate (pe.imageBase + parameters.tableRva)), 5)
  | 59 => some (.movFromOperand .eax
      (programLookupNativeMemoryOperand (some .eax) 0), 2)
  | 61 => some (.movToOperand
      (programLookupNativeEbpMemory (2 ^ 32 - 16)) .eax, 3)
  | 64 => some (.movFromOperand .eax
      (programLookupNativeEbpMemory (2 ^ 32 - 16)), 3)
  | 67 => some (.binary .compare (.register .eax)
      (programLookupNativeEbpMemory 8), 3)
  | 70 => some (.branchCondition .aboveOrEqual 0x0b 2, 2)
  | 72 => some (.movFromOperand .eax
      (programLookupNativeEbpMemory (2 ^ 32 - 12)), 3)
  | 75 => some (.binary .add (.register .eax) (.immediate 1), 3)
  | 78 => some (.movToOperand
      (programLookupNativeEbpMemory (2 ^ 32 - 4)) .eax, 3)
  | 81 => some (.jumpRel8 0x06, 2)
  | 83 => some (.movFromOperand .eax
      (programLookupNativeEbpMemory (2 ^ 32 - 12)), 3)
  | 86 => some (.movToOperand
      (programLookupNativeEbpMemory (2 ^ 32 - 8)) .eax, 3)
  | 89 => some (.movFromOperand .eax
      (programLookupNativeEbpMemory (2 ^ 32 - 4)), 3)
  | 92 => some (.binary .compare (.register .eax)
      (programLookupNativeEbpMemory (2 ^ 32 - 8)), 3)
  | 95 => some (.branchCondition .below 0xb6 2, 2)
  | 97 => some (.movFromOperand .eax (programLookupNativeMemoryOperand none
      (pe.imageBase + parameters.countRva)), 5)
  | 102 => some (.binary .compare
      (programLookupNativeEbpMemory (2 ^ 32 - 4)) (.register .eax), 3)
  | 105 => some (.branchCondition .aboveOrEqual 0x2d 2, 2)
  | 107 => some (.movFromOperand .edx
      (programLookupNativeEbpMemory (2 ^ 32 - 4)), 3)
  | 110 => some (.movToOperand (.register .eax) .edx, 2)
  | 112 => some (.shift .left (.register .eax) (.immediate 2), 3)
  | 115 => some (.binary .add (.register .eax) (.register .edx), 2)
  | 117 => some (.shift .left (.register .eax) (.immediate 3), 3)
  | 120 => some (.binary .add (.register .eax)
      (.immediate (pe.imageBase + parameters.tableRva)), 5)
  | 125 => some (.movFromOperand .eax
      (programLookupNativeMemoryOperand (some .eax) 0), 2)
  | 127 => some (.binary .compare
      (programLookupNativeEbpMemory 8) (.register .eax), 3)
  | 130 => some (.branchEqual true 0x14, 2)
  | 132 => some (.movFromOperand .edx
      (programLookupNativeEbpMemory (2 ^ 32 - 4)), 3)
  | 135 => some (.movToOperand (.register .eax) .edx, 2)
  | 137 => some (.shift .left (.register .eax) (.immediate 2), 3)
  | 140 => some (.binary .add (.register .eax) (.register .edx), 2)
  | 142 => some (.shift .left (.register .eax) (.immediate 3), 3)
  | 145 => some (.binary .add (.register .eax)
      (.immediate (pe.imageBase + parameters.tableRva)), 5)
  | 150 => some (.jumpRel8 0x05, 2)
  | 152 => some (.movRegImm .eax 0, 5)
  | 157 => some (.leave, 1)
  | 158 => some (.binary .xor (.register .edx) (.register .edx), 2)
  | 160 => some (.ret, 1)
  | _ => none

def programLookupNativeInstructionChecked (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) (offset : Nat) : Bool :=
  match executableInstructionWindow pe (parameters.entryRva + offset) with
  | none => false
  | some window =>
      decodeKernelX87FrameExact window == none &&
      StageA.Relational.X87.decodeCommandExact window == none &&
      match decodeInstructionExact window with
      | none => false
      | some decoded =>
          programLookupNativeExpectedInstruction? pe parameters offset ==
            some (decoded.instruction, decoded.size)

structure ProgramLookupNativeInstructionCertificate
    (pe : PE32) (parameters : ProgramLookupTemplateParameters) where
  offset : Nat
  checked : programLookupNativeInstructionChecked pe parameters offset = true

private def defaultProgramLookupDecodedInstruction : DecodedInstruction := {
  instruction := .nop
  size := 1
  trailing := []
}

def ProgramLookupNativeInstructionCertificate.window
    (certificate : ProgramLookupNativeInstructionCertificate pe parameters) :
    Bytes :=
  (executableInstructionWindow pe
    (parameters.entryRva + certificate.offset)).getD []

def ProgramLookupNativeInstructionCertificate.decoded
    (certificate : ProgramLookupNativeInstructionCertificate pe parameters) :
    DecodedInstruction :=
  (decodeInstructionExact certificate.window).getD
    defaultProgramLookupDecodedInstruction

theorem ProgramLookupNativeInstructionCertificate.facts
    (certificate : ProgramLookupNativeInstructionCertificate pe parameters) :
    executableInstructionWindow pe
        (parameters.entryRva + certificate.offset) = some certificate.window /\
      decodeKernelX87FrameExact certificate.window = none /\
      StageA.Relational.X87.decodeCommandExact certificate.window = none /\
      decodeInstructionExact certificate.window = some certificate.decoded /\
      programLookupNativeExpectedInstruction? pe parameters certificate.offset =
        some (certificate.decoded.instruction, certificate.decoded.size) := by
  have certificateChecked := certificate.checked
  rcases fetched : executableInstructionWindow pe
      (parameters.entryRva + certificate.offset) with _ | window
  · simp [programLookupNativeInstructionChecked, fetched] at certificateChecked
  rcases decodedExact : decodeInstructionExact window with _ | decoded
  · simp [programLookupNativeInstructionChecked, fetched, decodedExact] at certificateChecked
  have checked :
      (decodeKernelX87FrameExact window = none /\
        StageA.Relational.X87.decodeCommandExact window = none) /\
      programLookupNativeExpectedInstruction? pe parameters certificate.offset =
        some (decoded.instruction, decoded.size) := by
    simpa only [programLookupNativeInstructionChecked, fetched, decodedExact,
      Bool.and_eq_true, beq_iff_eq] using certificateChecked
  have windowExact : certificate.window = window := by
    simp [ProgramLookupNativeInstructionCertificate.window, fetched]
  have decodedValueExact : certificate.decoded = decoded := by
    simp [ProgramLookupNativeInstructionCertificate.decoded, windowExact,
      decodedExact]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simpa only [windowExact] using fetched
  · simpa only [windowExact] using checked.1.1
  · simpa only [windowExact] using checked.1.2
  · simpa only [windowExact, decodedValueExact] using decodedExact
  · simpa only [decodedValueExact] using checked.2

def programLookupNativeInstructionOffsets : List Nat :=
  [0, 1, 3, 6, 13, 18, 21, 23, 26, 29, 31, 33, 36, 38, 41, 44, 46,
    49, 51, 54, 59, 61, 64, 67, 70, 72, 75, 78, 81, 83, 86, 89, 92, 95,
    97, 102, 105, 107, 110, 112, 115, 117, 120, 125, 127, 130, 132, 135,
    137, 140, 142, 145, 150, 152, 157, 158, 160]

structure ProgramLookupNativeInstructionInventory
    (pe : PE32) (parameters : ProgramLookupTemplateParameters) where
  certificates : List (ProgramLookupNativeInstructionCertificate pe parameters)
  offsetsExact : certificates.map (fun certificate => certificate.offset) =
    programLookupNativeInstructionOffsets

theorem ProgramLookupNativeInstructionInventory.covers
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (offset : Nat) (member : offset ∈ programLookupNativeInstructionOffsets) :
    exists certificate, certificate ∈ inventory.certificates /\
      certificate.offset = offset := by
  rw [← inventory.offsetsExact] at member
  simpa only [List.mem_map] using member

noncomputable def ProgramLookupNativeInstructionInventory.certificateAt
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (offset : Nat) (member : offset ∈ programLookupNativeInstructionOffsets) :
    ProgramLookupNativeInstructionCertificate pe parameters :=
  Classical.choose (inventory.covers offset member)

theorem ProgramLookupNativeInstructionInventory.certificateAt_offset
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (offset : Nat) (member : offset ∈ programLookupNativeInstructionOffsets) :
    (inventory.certificateAt offset member).offset = offset :=
  (Classical.choose_spec (inventory.covers offset member)).2

def programLookupNativeExpectedDecoded? (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) (offset : Nat) :
    Option DecodedInstruction :=
  (programLookupNativeExpectedInstruction? pe parameters offset).map
    (fun expected => {
      instruction := expected.1
      size := expected.2
      trailing := []
    })

/-- Execute an already checked decoded instruction through the same reviewed
symbolic semantics used by `stepPE32Instruction`. -/
def stepDecodedPE32Instruction (pe : PE32) (imports : List PEImport)
    (rva undefinedSlot : Nat) (decoded : DecodedInstruction)
    (state : MachineState) : PE32InstructionExecution :=
  match executeInstruction pe imports rva undefinedSlot decoded initialSymbolic with
  | none => .fault
  | some (.next symbolic) =>
      let concrete := symbolic.eval state
      match concrete.outcome with
      | some _ => .fault
      | none => .running (rva + decoded.size) (undefinedSlot + 1)
          (concreteBehaviorNextMachineState concrete state)
  | some (.stop symbolic) =>
      let concrete := symbolic.eval state
      match concrete.outcome with
      | none => .fault
      | some outcome => .stopped outcome
          (concreteBehaviorNextMachineState concrete state)

theorem stepDecodedPE32Instruction_congr
    (left right : DecodedInstruction)
    (instructionExact : left.instruction = right.instruction)
    (sizeExact : left.size = right.size)
    (pe : PE32) (imports : List PEImport) (rva undefinedSlot : Nat)
    (state : MachineState) :
    stepDecodedPE32Instruction pe imports rva undefinedSlot left state =
      stepDecodedPE32Instruction pe imports rva undefinedSlot right state := by
  cases left with
  | mk leftInstruction leftSize leftTrailing =>
      cases right with
      | mk rightInstruction rightSize rightTrailing =>
          cases instructionExact
          cases sizeExact
          rfl

theorem ProgramLookupNativeInstructionCertificate.stepKernelExact
    (certificate : ProgramLookupNativeInstructionCertificate pe parameters)
    (imports : List PEImport) (undefinedSlot : Nat) (state : MachineState) :
    stepKernelPE32Instruction pe imports
        (.running (parameters.entryRva + certificate.offset) undefinedSlot state) =
      stepDecodedPE32Instruction pe imports
        (parameters.entryRva + certificate.offset) undefinedSlot
        certificate.decoded state := by
  simp [stepKernelPE32Instruction, certificate.facts.1,
    certificate.facts.2.1, stepKernelX87Command?, certificate.facts.2.2.1,
    stepPE32Instruction, certificate.facts.2.2.2.1,
    stepDecodedPE32Instruction]
  rfl

/-- Lift one exact ordinary instruction result through the native call/event
machine.  Keeping this conversion separate prevents generated instruction
certificates from choosing a native successor. -/
def continueProgramLookupNativeExecution (environment : NativeEnvironment)
    (before : NativeExecution) (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) :
    PE32InstructionExecution -> NativeExecution
  | .running nextRva nextSlot nextState =>
      .running nextRva nextSlot nextState calls eventIndex events
  | .stopped outcome nextState =>
      nextNativeExecution environment before outcome nextState calls eventIndex events
  | .fault => .fault

theorem ProgramLookupNativeInstructionCertificate.stepNativeExact
    (certificate : ProgramLookupNativeInstructionCertificate pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + certificate.offset) undefinedSlot state
          calls eventIndex events) =
      continueProgramLookupNativeExecution environment
        (.running (parameters.entryRva + certificate.offset) undefinedSlot state
          calls eventIndex events) calls eventIndex events
        (stepDecodedPE32Instruction pe imports
          (parameters.entryRva + certificate.offset) undefinedSlot
          certificate.decoded state) := by
  rw [stepNativeExecution, certificate.stepKernelExact]
  rfl

/-- Candidate-independent execution of one reviewed template instruction. -/
def stepProgramLookupNativeExpectedInstruction (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (offset undefinedSlot : Nat)
    (state : MachineState) (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) : NativeExecution :=
  match programLookupNativeExpectedDecoded? pe parameters offset with
  | none => .fault
  | some decoded =>
      continueProgramLookupNativeExecution environment
        (.running (parameters.entryRva + offset) undefinedSlot state calls
          eventIndex events) calls eventIndex events
        (stepDecodedPE32Instruction pe imports
          (parameters.entryRva + offset) undefinedSlot decoded state)

theorem ProgramLookupNativeInstructionInventory.stepNativeAt
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (offset : Nat) (member : offset ∈ programLookupNativeInstructionOffsets)
    (undefinedSlot : Nat) (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + offset) undefinedSlot state calls
          eventIndex events) =
      stepProgramLookupNativeExpectedInstruction pe imports environment
        parameters offset undefinedSlot state calls eventIndex events := by
  let certificate := inventory.certificateAt offset member
  have offsetExact := inventory.certificateAt_offset offset member
  have exact := certificate.stepNativeExact imports environment undefinedSlot
    state calls eventIndex events
  rw [offsetExact] at exact
  rw [exact]
  unfold stepProgramLookupNativeExpectedInstruction
  have expected := certificate.facts.2.2.2.2
  unfold programLookupNativeExpectedDecoded?
  rw [offsetExact] at expected
  rw [expected]
  simp only [Option.map_some]
  apply congrArg (continueProgramLookupNativeExecution environment
    (.running (parameters.entryRva + offset) undefinedSlot state calls eventIndex
      events) calls eventIndex events)
  apply stepDecodedPE32Instruction_congr
  · rfl
  · rfl

/-- The state computed by one reviewed template instruction.  The fallback is
unreachable in every theorem below: the exact decoded semantics separately
prove that the selected instruction has an ordinary running successor. -/
def programLookupNativeExpectedStepState (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (parameters : ProgramLookupTemplateParameters)
    (offset undefinedSlot : Nat) (state : MachineState) : MachineState :=
  match stepProgramLookupNativeExpectedInstruction pe imports environment
      parameters offset undefinedSlot state [] 0 [] with
  | .running _ _ nextState _ _ _ => nextState
  | _ => state

theorem programLookupNativeExpectedStepState_of_running
    (running : exists nextState,
      stepProgramLookupNativeExpectedInstruction pe imports environment
          parameters offset undefinedSlot state [] 0 [] =
        .running nextRva nextUndefinedSlot nextState [] 0 []) :
    stepProgramLookupNativeExpectedInstruction pe imports environment
        parameters offset undefinedSlot state [] 0 [] =
      .running nextRva nextUndefinedSlot
        (programLookupNativeExpectedStepState pe imports environment parameters
          offset undefinedSlot state) [] 0 [] := by
  obtain ⟨nextState, running⟩ := running
  unfold programLookupNativeExpectedStepState
  rw [running]

@[simp] theorem programLookupNativeImmediateIsNotMaskedZero
    (amount : Nat) (positive : 0 < amount) (belowMask : amount < 32) :
    ShiftCount.isMaskedZero (.immediate amount) = false := by
  simp [ShiftCount.isMaskedZero, Nat.mod_eq_of_lt belowMask,
    Nat.ne_of_gt positive]

@[simp] theorem programLookupNativeImmediateExpression
    (state : SymbolicBehavior) (amount : Nat) (belowMask : amount < 32) :
    ShiftCount.expression state (.immediate amount) = .constant amount := by
  simp [ShiftCount.expression, Nat.mod_eq_of_lt belowMask]

theorem ProgramLookupNativeInstructionInventory.stepLinearExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (offset nextOffset undefinedSlot : Nat) (state : MachineState)
    (member : offset ∈ programLookupNativeInstructionOffsets)
    (shape : stepProgramLookupNativeExpectedInstruction pe imports environment
      parameters offset undefinedSlot state [] 0 [] =
        .running (parameters.entryRva + nextOffset) (undefinedSlot + 1)
          (programLookupNativeExpectedStepState pe imports environment parameters
            offset undefinedSlot state) [] 0 []) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + offset) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + nextOffset) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          offset undefinedSlot state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment offset member]
  exact shape

theorem programLookupNativeExpectedStep89Shape
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        89 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 92) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          89 undefinedSlot state) [] 0 [] := by
  simp (config := { maxSteps := 200000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, Expr.offset,
      readOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]

theorem ProgramLookupNativeInstructionInventory.step89Exact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 92) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          89 undefinedSlot state) [] 0 [] := by
  apply inventory.stepLinearExact imports environment 89 92 undefinedSlot state
    (by decide)
  exact programLookupNativeExpectedStep89Shape pe imports environment parameters
    undefinedSlot state

def programLookupNativeGuardResult (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot : Nat) (state : MachineState) : MachineState :=
  let state92 := programLookupNativeExpectedStepState pe imports environment
    parameters 89 undefinedSlot state
  let state95 := programLookupNativeExpectedStepState pe imports environment
    parameters 92 (undefinedSlot + 1) state92
  programLookupNativeExpectedStepState pe imports environment parameters 95
    (undefinedSlot + 2) state95

theorem programLookupNativeStep95Taken
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (carry : programLookupFlagIs state 0 true) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        95 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 23) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 95
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have target :
      relativeTarget8 (parameters.entryRva + 97) 182 =
        parameters.entryRva + 23 := by
    exact programLookupRelativeTarget8Backward parameters 97 182 23
      (by omega) (by omega) (by omega) (by omega)
  have carrySet :
      state.eflags.extractLsb' 0 1 = 1#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using carry
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      conditionExpression, evalFlagBit, programLookupFlagIs, carrySet, target,
      Nat.add_assoc] at carry ⊢

theorem programLookupNativeStep95Exit
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (carry : programLookupFlagIs state 0 false) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        95 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 97) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 95
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have carryClear :
      state.eflags.extractLsb' 0 1 = 0#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using carry
  have carryNotSet :
      ¬ state.eflags.extractLsb' 0 1 = 1#1 := by
    rw [carryClear]
    decide
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      conditionExpression, evalFlagBit, programLookupFlagIs, carryNotSet,
      Nat.add_assoc] at carry ⊢

theorem programLookupNativeStep70Lower
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (carry : programLookupFlagIs state 0 true) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        70 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 72) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 70
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have carrySet :
      state.eflags.extractLsb' 0 1 = 1#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using carry
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      conditionExpression, evalFlagBit, programLookupFlagIs, carrySet,
      Nat.add_assoc] at carry ⊢

theorem programLookupNativeStep70Upper
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (carry : programLookupFlagIs state 0 false) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        70 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 83) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 70
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have target :
      relativeTarget8 (parameters.entryRva + 72) 11 =
        parameters.entryRva + 83 := by
    exact programLookupRelativeTarget8Forward parameters 72 11 83
      (by omega) (by omega) (by omega)
  have carryClear :
      state.eflags.extractLsb' 0 1 = 0#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using carry
  have carryNotSet :
      ¬ state.eflags.extractLsb' 0 1 = 1#1 := by
    rw [carryClear]
    decide
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      conditionExpression, evalFlagBit, programLookupFlagIs, carryNotSet, target,
      Nat.add_assoc] at carry ⊢

inductive ProgramLookupNativeLoopLinearSuccessor : Nat -> Nat -> Prop
  | offset23 : ProgramLookupNativeLoopLinearSuccessor 23 26
  | offset26 : ProgramLookupNativeLoopLinearSuccessor 26 29
  | offset29 : ProgramLookupNativeLoopLinearSuccessor 29 31
  | offset31 : ProgramLookupNativeLoopLinearSuccessor 31 33
  | offset33 : ProgramLookupNativeLoopLinearSuccessor 33 36
  | offset36 : ProgramLookupNativeLoopLinearSuccessor 36 38
  | offset38 : ProgramLookupNativeLoopLinearSuccessor 38 41
  | offset41 : ProgramLookupNativeLoopLinearSuccessor 41 44
  | offset44 : ProgramLookupNativeLoopLinearSuccessor 44 46
  | offset46 : ProgramLookupNativeLoopLinearSuccessor 46 49
  | offset49 : ProgramLookupNativeLoopLinearSuccessor 49 51
  | offset51 : ProgramLookupNativeLoopLinearSuccessor 51 54
  | offset54 : ProgramLookupNativeLoopLinearSuccessor 54 59
  | offset59 : ProgramLookupNativeLoopLinearSuccessor 59 61
  | offset61 : ProgramLookupNativeLoopLinearSuccessor 61 64
  | offset64 : ProgramLookupNativeLoopLinearSuccessor 64 67
  | offset67 : ProgramLookupNativeLoopLinearSuccessor 67 70
  | offset72 : ProgramLookupNativeLoopLinearSuccessor 72 75
  | offset75 : ProgramLookupNativeLoopLinearSuccessor 75 78
  | offset78 : ProgramLookupNativeLoopLinearSuccessor 78 81
  | offset83 : ProgramLookupNativeLoopLinearSuccessor 83 86
  | offset86 : ProgramLookupNativeLoopLinearSuccessor 86 89

theorem programLookupNativeExpectedLoopLinearShape
    (edge : ProgramLookupNativeLoopLinearSuccessor offset nextOffset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        offset undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + nextOffset) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          offset undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  cases edge <;>
    simp (config := { maxSteps := 200000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
        Expr.subNormalized, Expr.offset, readOperand32, writeOperand32,
        Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
        programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
        StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem ProgramLookupNativeInstructionInventory.stepLoopLinearExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (edge : ProgramLookupNativeLoopLinearSuccessor offset nextOffset)
    (undefinedSlot : Nat) (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + offset) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + nextOffset) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          offset undefinedSlot state) [] 0 [] := by
  apply inventory.stepLinearExact imports environment offset nextOffset
    undefinedSlot state
  · cases edge <;> decide
  · exact programLookupNativeExpectedLoopLinearShape edge pe imports environment
      parameters undefinedSlot state

inductive ProgramLookupNativeFinishOffset : Nat -> Prop
  | offset97 : ProgramLookupNativeFinishOffset 97
  | offset102 : ProgramLookupNativeFinishOffset 102
  | offset105 : ProgramLookupNativeFinishOffset 105
  | offset107 : ProgramLookupNativeFinishOffset 107
  | offset110 : ProgramLookupNativeFinishOffset 110
  | offset112 : ProgramLookupNativeFinishOffset 112
  | offset115 : ProgramLookupNativeFinishOffset 115
  | offset117 : ProgramLookupNativeFinishOffset 117
  | offset120 : ProgramLookupNativeFinishOffset 120
  | offset125 : ProgramLookupNativeFinishOffset 125
  | offset127 : ProgramLookupNativeFinishOffset 127
  | offset130 : ProgramLookupNativeFinishOffset 130
  | offset132 : ProgramLookupNativeFinishOffset 132
  | offset135 : ProgramLookupNativeFinishOffset 135
  | offset137 : ProgramLookupNativeFinishOffset 137
  | offset140 : ProgramLookupNativeFinishOffset 140
  | offset142 : ProgramLookupNativeFinishOffset 142
  | offset145 : ProgramLookupNativeFinishOffset 145
  | offset150 : ProgramLookupNativeFinishOffset 150
  | offset152 : ProgramLookupNativeFinishOffset 152

theorem programLookupNativeFinishStep_memory
    (offsetSupported : ProgramLookupNativeFinishOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).memory = state.memory := by
  cases offsetSupported <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
        Expr.subNormalized, readOperand32, writeOperand32,
        Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
        programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
        StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites, conditionExpression, evalFlagBit]

inductive ProgramLookupNativeFinishLinearSuccessor : Nat -> Nat -> Prop
  | offset97 : ProgramLookupNativeFinishLinearSuccessor 97 102
  | offset102 : ProgramLookupNativeFinishLinearSuccessor 102 105
  | offset107 : ProgramLookupNativeFinishLinearSuccessor 107 110
  | offset110 : ProgramLookupNativeFinishLinearSuccessor 110 112
  | offset112 : ProgramLookupNativeFinishLinearSuccessor 112 115
  | offset115 : ProgramLookupNativeFinishLinearSuccessor 115 117
  | offset117 : ProgramLookupNativeFinishLinearSuccessor 117 120
  | offset120 : ProgramLookupNativeFinishLinearSuccessor 120 125
  | offset125 : ProgramLookupNativeFinishLinearSuccessor 125 127
  | offset127 : ProgramLookupNativeFinishLinearSuccessor 127 130
  | offset132 : ProgramLookupNativeFinishLinearSuccessor 132 135
  | offset135 : ProgramLookupNativeFinishLinearSuccessor 135 137
  | offset137 : ProgramLookupNativeFinishLinearSuccessor 137 140
  | offset140 : ProgramLookupNativeFinishLinearSuccessor 140 142
  | offset142 : ProgramLookupNativeFinishLinearSuccessor 142 145
  | offset145 : ProgramLookupNativeFinishLinearSuccessor 145 150
  | offset152 : ProgramLookupNativeFinishLinearSuccessor 152 157

theorem programLookupNativeExpectedFinishLinearShape
    (edge : ProgramLookupNativeFinishLinearSuccessor offset nextOffset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        offset undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + nextOffset) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          offset undefinedSlot state) [] 0 [] := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]

theorem ProgramLookupNativeInstructionInventory.stepFinishLinearExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (edge : ProgramLookupNativeFinishLinearSuccessor offset nextOffset)
    (undefinedSlot : Nat) (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + offset) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + nextOffset) (undefinedSlot + 1)
        (programLookupNativeExpectedStepState pe imports environment parameters
          offset undefinedSlot state) [] 0 [] := by
  apply inventory.stepLinearExact imports environment offset nextOffset
    undefinedSlot state
  · cases edge <;> decide
  · exact programLookupNativeExpectedFinishLinearShape edge pe imports environment
      parameters undefinedSlot state

def programLookupNativeFinishCountResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  let state102 := programLookupNativeExpectedStepState pe imports environment
    parameters 97 undefinedSlot state
  programLookupNativeExpectedStepState pe imports environment parameters 102
    (undefinedSlot + 1) state102

def programLookupNativeFinishCountBranchResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeExpectedStepState pe imports environment parameters 105
    undefinedSlot state

def programLookupNativeFinishRecordResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  let state110 := programLookupNativeExpectedStepState pe imports environment
    parameters 107 undefinedSlot state
  let state112 := programLookupNativeExpectedStepState pe imports environment
    parameters 110 (undefinedSlot + 1) state110
  let state115 := programLookupNativeExpectedStepState pe imports environment
    parameters 112 (undefinedSlot + 2) state112
  let state117 := programLookupNativeExpectedStepState pe imports environment
    parameters 115 (undefinedSlot + 3) state115
  let state120 := programLookupNativeExpectedStepState pe imports environment
    parameters 117 (undefinedSlot + 4) state117
  let state125 := programLookupNativeExpectedStepState pe imports environment
    parameters 120 (undefinedSlot + 5) state120
  programLookupNativeExpectedStepState pe imports environment parameters 125
    (undefinedSlot + 6) state125

def programLookupNativeFinishCompareResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeExpectedStepState pe imports environment parameters 127
    undefinedSlot state

def programLookupNativeFinishMatchBranchResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeExpectedStepState pe imports environment parameters 130
    undefinedSlot state

def programLookupNativeFinishPointerResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  let state135 := programLookupNativeExpectedStepState pe imports environment
    parameters 132 undefinedSlot state
  let state137 := programLookupNativeExpectedStepState pe imports environment
    parameters 135 (undefinedSlot + 1) state135
  let state140 := programLookupNativeExpectedStepState pe imports environment
    parameters 137 (undefinedSlot + 2) state137
  let state142 := programLookupNativeExpectedStepState pe imports environment
    parameters 140 (undefinedSlot + 3) state140
  let state145 := programLookupNativeExpectedStepState pe imports environment
    parameters 142 (undefinedSlot + 4) state142
  let state150 := programLookupNativeExpectedStepState pe imports environment
    parameters 145 (undefinedSlot + 5) state145
  programLookupNativeExpectedStepState pe imports environment parameters 150
    (undefinedSlot + 6) state150

def programLookupNativeFinishZeroResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeExpectedStepState pe imports environment parameters 152
    undefinedSlot state

theorem ProgramLookupNativeInstructionInventory.runFinishCountExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 2
        (.running (parameters.entryRva + 97) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 105) (undefinedSlot + 2)
        (programLookupNativeFinishCountResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset97]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset102]
  rfl

theorem ProgramLookupNativeInstructionInventory.runFinishRecordExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 7
        (.running (parameters.entryRva + 107) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 127) (undefinedSlot + 7)
        (programLookupNativeFinishRecordResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset107]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset110]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset112]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset115]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset117]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset120]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset125]
  rfl

theorem programLookupNativeStep105Taken
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (carry : programLookupFlagIs state 0 false) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        105 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 152) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 105
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have target :
      relativeTarget8 (parameters.entryRva + 107) 45 =
        parameters.entryRva + 152 := by
    exact programLookupRelativeTarget8Forward parameters 107 45 152
      (by omega) (by omega) (by omega)
  have carryClear :
      state.eflags.extractLsb' 0 1 = 0#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using carry
  have carryNotSet :
      ¬ state.eflags.extractLsb' 0 1 = 1#1 := by
    rw [carryClear]
    decide
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, conditionExpression, evalFlagBit,
      programLookupFlagIs, carryNotSet, target, Nat.add_assoc] at carry ⊢

theorem programLookupNativeStep105NotTaken
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (carry : programLookupFlagIs state 0 true) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        105 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 107) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 105
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have carrySet :
      state.eflags.extractLsb' 0 1 = 1#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using carry
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, conditionExpression, evalFlagBit,
      programLookupFlagIs, carrySet, Nat.add_assoc] at carry ⊢

theorem programLookupNativeStep130Taken
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (zeroClear : programLookupFlagIs state 6 false) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        130 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 152) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 130
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have target :
      relativeTarget8 (parameters.entryRva + 132) 20 =
        parameters.entryRva + 152 := by
    exact programLookupRelativeTarget8Forward parameters 132 20 152
      (by omega) (by omega) (by omega)
  have zeroClear' :
      state.eflags.extractLsb' 6 1 = 0#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using zeroClear
  have zeroNotSet :
      ¬ state.eflags.extractLsb' 6 1 = 1#1 := by
    rw [zeroClear']
    decide
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, conditionExpression, evalFlagBit,
      programLookupFlagIs, zeroNotSet, target, Nat.add_assoc] at zeroClear ⊢

theorem programLookupNativeStep130NotTaken
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) (zeroSet : programLookupFlagIs state 6 true) :
    stepProgramLookupNativeExpectedInstruction pe imports environment parameters
        130 undefinedSlot state [] 0 [] =
      .running (parameters.entryRva + 132) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 130
          undefinedSlot state) [] 0 [] := by
  apply programLookupNativeExpectedStepState_of_running
  have zeroSet' :
      state.eflags.extractLsb' 6 1 = 1#1 := by
    simpa [programLookupFlagIs, evalFlagBit] using zeroSet
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, conditionExpression, evalFlagBit,
      programLookupFlagIs, zeroSet', Nat.add_assoc] at zeroSet ⊢

theorem ProgramLookupNativeInstructionInventory.stepJump150Exact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (undefinedSlot : Nat) (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 150) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 157) 0
        (programLookupNativeExpectedStepState pe imports environment parameters 150
          undefinedSlot state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 150 (by decide)]
  have target :
      relativeTarget8 (parameters.entryRva + 152) 5 =
        parameters.entryRva + 157 := by
    exact programLookupRelativeTarget8Forward parameters 152 5 157
      (by omega) (by omega) (by omega)
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites, target,
      Nat.add_assoc]

theorem ProgramLookupNativeInstructionInventory.runFinishPointerExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 7
        (.running (parameters.entryRva + 132) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 157) 0
        (programLookupNativeFinishPointerResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset132]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset135]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset137]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset140]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset142]
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset145]
  rw [runProgramLookupNativeFuel,
    inventory.stepJump150Exact imports environment]
  rfl

theorem ProgramLookupNativeInstructionInventory.runFinishZeroExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 1
        (.running (parameters.entryRva + 152) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 157) (undefinedSlot + 1)
        (programLookupNativeFinishZeroResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepFinishLinearExact imports environment .offset152]
  rfl

def programLookupNativeMidpointResult (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot : Nat) (state : MachineState) : MachineState :=
  let state26 := programLookupNativeExpectedStepState pe imports environment
    parameters 23 undefinedSlot state
  let state29 := programLookupNativeExpectedStepState pe imports environment
    parameters 26 (undefinedSlot + 1) state26
  let state31 := programLookupNativeExpectedStepState pe imports environment
    parameters 29 (undefinedSlot + 2) state29
  let state33 := programLookupNativeExpectedStepState pe imports environment
    parameters 31 (undefinedSlot + 3) state31
  let state36 := programLookupNativeExpectedStepState pe imports environment
    parameters 33 (undefinedSlot + 4) state33
  let state38 := programLookupNativeExpectedStepState pe imports environment
    parameters 36 (undefinedSlot + 5) state36
  programLookupNativeExpectedStepState pe imports environment parameters 38
    (undefinedSlot + 6) state38

theorem ProgramLookupNativeInstructionInventory.runMidpointExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 7
        (.running (parameters.entryRva + 23) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 41) (undefinedSlot + 7)
        (programLookupNativeMidpointResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset23]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset26]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset29]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset31]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset33]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset36]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset38]
  rfl

def programLookupNativeRecordPreWriteResult (pe : PE32)
    (imports : List PEImport)
    (environment : NativeEnvironment) (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot : Nat) (state : MachineState) : MachineState :=
  let state44 := programLookupNativeExpectedStepState pe imports environment
    parameters 41 undefinedSlot state
  let state46 := programLookupNativeExpectedStepState pe imports environment
    parameters 44 (undefinedSlot + 1) state44
  let state49 := programLookupNativeExpectedStepState pe imports environment
    parameters 46 (undefinedSlot + 2) state46
  let state51 := programLookupNativeExpectedStepState pe imports environment
    parameters 49 (undefinedSlot + 3) state49
  let state54 := programLookupNativeExpectedStepState pe imports environment
    parameters 51 (undefinedSlot + 4) state51
  let state59 := programLookupNativeExpectedStepState pe imports environment
    parameters 54 (undefinedSlot + 5) state54
  programLookupNativeExpectedStepState pe imports environment parameters 59
    (undefinedSlot + 6) state59

def programLookupNativeRecordResult (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot : Nat) (state : MachineState) : MachineState :=
  let state61 := programLookupNativeRecordPreWriteResult pe imports environment
    parameters undefinedSlot state
  programLookupNativeExpectedStepState pe imports environment parameters 61
    (undefinedSlot + 7) state61

theorem programLookupNativeStep41_edx
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 41
      undefinedSlot state).registers.edx =
      Memory.read32 state.memory
        (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 12)) := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep44_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 44
      undefinedSlot state).registers.eax = state.registers.edx := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep44_edx
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 44
      undefinedSlot state).registers.edx = state.registers.edx := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep46_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 46
      undefinedSlot state).registers.eax = state.registers.eax <<< 2 := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep46_edx
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 46
      undefinedSlot state).registers.edx = state.registers.edx := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep49_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 49
      undefinedSlot state).registers.eax =
      state.registers.eax + state.registers.edx := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep51_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 51
      undefinedSlot state).registers.eax = state.registers.eax <<< 3 := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep54_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 54
      undefinedSlot state).registers.eax =
      state.registers.eax +
        BitVec.ofNat 32 (pe.imageBase + parameters.tableRva) := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, readOperand32, writeOperand32,
      Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      evalInputRegAddNormalizedConstant]

theorem programLookupNativeStep59_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 59
      undefinedSlot state).registers.eax =
      Memory.read32 state.memory state.registers.eax := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

inductive ProgramLookupNativeRecordReadOnlyOffset : Nat -> Prop
  | offset41 : ProgramLookupNativeRecordReadOnlyOffset 41
  | offset44 : ProgramLookupNativeRecordReadOnlyOffset 44
  | offset46 : ProgramLookupNativeRecordReadOnlyOffset 46
  | offset49 : ProgramLookupNativeRecordReadOnlyOffset 49
  | offset51 : ProgramLookupNativeRecordReadOnlyOffset 51
  | offset54 : ProgramLookupNativeRecordReadOnlyOffset 54
  | offset59 : ProgramLookupNativeRecordReadOnlyOffset 59

theorem programLookupNativeRecordStep_memory
    (edge : ProgramLookupNativeRecordReadOnlyOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).memory = state.memory := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, readOperand32, writeOperand32,
        Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
        programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
        StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        evalInputRegAddNormalizedConstant]

theorem programLookupNativeRecordPreWriteResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeRecordPreWriteResult pe imports environment parameters
      undefinedSlot state).memory = state.memory := by
  by_cases baseZero : pe.imageBase + parameters.tableRva = 0
  all_goals simp (config := { maxSteps := 1000000 })
    [programLookupNativeRecordPreWriteResult,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32,
      Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites, baseZero]

theorem programLookupNativeRecordPreWriteResult_ebp
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeRecordPreWriteResult pe imports environment parameters
      undefinedSlot state).registers.ebp = state.registers.ebp := by
  by_cases baseZero : pe.imageBase + parameters.tableRva = 0
  all_goals simp (config := { maxSteps := 1000000 })
    [programLookupNativeRecordPreWriteResult,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32,
      Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites, baseZero]

theorem programLookupNativeRecordPreWriteResult_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot midpoint : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (framePointerExact : state.registers.ebp =
      programLookupSavedEbpSlot before.registers.esp)
    (midpointExact : Memory.read32 state.memory
      (programLookupMidpointSlot before.registers.esp) = BitVec.ofNat 32 midpoint)
    (tableExact : Memory.read32 state.memory
      (programLookupTableAddress pe parameters.tableRva midpoint) =
        BitVec.ofNat 32 record.sourceRva) :
    (programLookupNativeRecordPreWriteResult pe imports environment parameters
      undefinedSlot state).registers.eax = BitVec.ofNat 32 record.sourceRva := by
  have midpointAddress :
      programLookupSavedEbpSlot before.registers.esp +
          BitVec.ofNat 32 (2 ^ 32 - 12) =
        programLookupMidpointSlot before.registers.esp := by
    unfold programLookupSavedEbpSlot programLookupMidpointSlot
      programLookupFrameByte
    bv_decide
  let state44 := programLookupNativeExpectedStepState pe imports environment
    parameters 41 undefinedSlot state
  let state46 := programLookupNativeExpectedStepState pe imports environment
    parameters 44 (undefinedSlot + 1) state44
  let state49 := programLookupNativeExpectedStepState pe imports environment
    parameters 46 (undefinedSlot + 2) state46
  let state51 := programLookupNativeExpectedStepState pe imports environment
    parameters 49 (undefinedSlot + 3) state49
  let state54 := programLookupNativeExpectedStepState pe imports environment
    parameters 51 (undefinedSlot + 4) state51
  let state59 := programLookupNativeExpectedStepState pe imports environment
    parameters 54 (undefinedSlot + 5) state54
  have mem44 : state44.memory = state.memory :=
    programLookupNativeRecordStep_memory .offset41 pe imports environment
      parameters undefinedSlot state
  have mem46 : state46.memory = state44.memory :=
    programLookupNativeRecordStep_memory .offset44 pe imports environment
      parameters (undefinedSlot + 1) state44
  have mem49 : state49.memory = state46.memory :=
    programLookupNativeRecordStep_memory .offset46 pe imports environment
      parameters (undefinedSlot + 2) state46
  have mem51 : state51.memory = state49.memory :=
    programLookupNativeRecordStep_memory .offset49 pe imports environment
      parameters (undefinedSlot + 3) state49
  have mem54 : state54.memory = state51.memory :=
    programLookupNativeRecordStep_memory .offset51 pe imports environment
      parameters (undefinedSlot + 4) state51
  have mem59 : state59.memory = state54.memory :=
    programLookupNativeRecordStep_memory .offset54 pe imports environment
      parameters (undefinedSlot + 5) state54
  unfold programLookupNativeRecordPreWriteResult
  rw [programLookupNativeStep59_eax, mem59, mem54, mem51, mem49, mem46,
    mem44]
  rw [programLookupNativeStep54_eax, programLookupNativeStep51_eax,
    programLookupNativeStep49_eax, programLookupNativeStep46_eax,
    programLookupNativeStep44_eax, programLookupNativeStep41_edx]
  rw [programLookupNativeStep46_edx, programLookupNativeStep44_edx,
    programLookupNativeStep41_edx]
  rw [framePointerExact, midpointAddress, midpointExact]
  rw [programLookupTableAddressWord, tableExact]

theorem programLookupNativeRecordResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeRecordResult pe imports environment parameters
      undefinedSlot state).memory =
      state.memory.write32
        (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 16))
        (programLookupNativeRecordPreWriteResult pe imports environment parameters
          undefinedSlot state).registers.eax := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeRecordResult, programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      writeOperand32,
      Addressing.expression, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      programLookupNativeRecordPreWriteResult_memory,
      programLookupNativeRecordPreWriteResult_ebp]

theorem ProgramLookupNativeInstructionInventory.runRecordExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 8
        (.running (parameters.entryRva + 41) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 64) (undefinedSlot + 8)
        (programLookupNativeRecordResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset41]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset44]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset46]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset49]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset51]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset54]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset59]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset61]
  rfl

def programLookupNativeCompareResult (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot : Nat) (state : MachineState) : MachineState :=
  let state67 := programLookupNativeExpectedStepState pe imports environment
    parameters 64 undefinedSlot state
  programLookupNativeExpectedStepState pe imports environment parameters 67
    (undefinedSlot + 1) state67

theorem ProgramLookupNativeInstructionInventory.runCompareExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 2
        (.running (parameters.entryRva + 64) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 70) (undefinedSlot + 2)
        (programLookupNativeCompareResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset64]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset67]
  rfl

def programLookupNativeLowerUpdateResult (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    MachineState :=
  let state75 := programLookupNativeExpectedStepState pe imports environment
    parameters 72 undefinedSlot state
  let state78 := programLookupNativeExpectedStepState pe imports environment
    parameters 75 (undefinedSlot + 1) state75
  programLookupNativeExpectedStepState pe imports environment parameters 78
    (undefinedSlot + 2) state78

theorem ProgramLookupNativeInstructionInventory.stepJump81Exact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (undefinedSlot : Nat) (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 81) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 89) 0
        (programLookupNativeExpectedStepState pe imports environment parameters
          81 undefinedSlot state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 81 (by decide)]
  have target :
      relativeTarget8 (parameters.entryRva + 83) 6 =
        parameters.entryRva + 89 := by
    exact programLookupRelativeTarget8Forward parameters 83 6 89
      (by omega) (by omega) (by omega)
  simp (config := { maxSteps := 200000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites, target,
      Nat.add_assoc]

theorem ProgramLookupNativeInstructionInventory.runLowerUpdateExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (undefinedSlot : Nat) (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 4
        (.running (parameters.entryRva + 72) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 89) 0
        (programLookupNativeExpectedStepState pe imports environment parameters
          81 (undefinedSlot + 3)
            (programLookupNativeLowerUpdateResult pe imports environment
              parameters undefinedSlot state)) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset72]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset75]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset78]
  rw [runProgramLookupNativeFuel,
    inventory.stepJump81Exact imports environment (undefinedSlot + 3)]
  rfl

def programLookupNativeUpperUpdateResult (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (state : MachineState) :
    MachineState :=
  let state86 := programLookupNativeExpectedStepState pe imports environment
    parameters 83 0 state
  programLookupNativeExpectedStepState pe imports environment parameters 86 1
    state86

theorem ProgramLookupNativeInstructionInventory.runUpperUpdateExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 2
        (.running (parameters.entryRva + 83) 0 state [] 0 []) =
      .running (parameters.entryRva + 89) 2
        (programLookupNativeUpperUpdateResult pe imports environment parameters
          state) [] 0 [] := by
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset83]
  rw [runProgramLookupNativeFuel,
    inventory.stepLoopLinearExact imports environment .offset86]
  rfl

/-- Smallest cacheable native-template computation unit.  This shape theorem is
used to keep the epilogue proof from unfolding any preceding lookup block. -/
theorem ProgramLookupNativeInstructionInventory.stepLeaveShape
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent) :
    exists nextState,
      stepNativeExecution pe imports environment
          (.running (parameters.entryRva + 157) undefinedSlot state calls
            eventIndex events) =
        .running (parameters.entryRva + 158) (undefinedSlot + 1) nextState calls
          eventIndex events := by
  rw [inventory.stepNativeAt imports environment 157 (by decide)]
  simp (config := { maxSteps := 200000 })
    [stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

/-- The normalization performed by an ordinary decoded instruction on the x87
component.  Only the eight architectural stack slots are retained by the
symbolic evaluator. -/
def programLookupNativeOrdinaryX87 (state : MachineState) : X87MachineState := {
  stack := fun index =>
    (Option.map (X87Expr.eval state ∘ X87Expr.inputStack)
      (List.range 8)[index]?).getD (BitVec.ofNat 80 0)
  control := (BitVec.setWidth 32 state.x87.control).extractLsb' 0 16
  status := (BitVec.setWidth 32 state.x87.status).extractLsb' 0 16
  semantics := state.x87.semantics
}

theorem programLookupNativeOrdinaryX87_stack (state : MachineState)
    (index : Nat) (inside : index < 8) :
    (programLookupNativeOrdinaryX87 state).stack index = state.x87.stack index := by
  simp [programLookupNativeOrdinaryX87, Function.comp_apply,
    StageA.Formal.X87Expr.eval, inside]

theorem programLookupNativeOrdinaryX87_preserved (state : MachineState) :
    ProgramLookupArchitecturalX87Preserved state
      { state with x87 := programLookupNativeOrdinaryX87 state } := by
  refine {
    stack := fun index inside => programLookupNativeOrdinaryX87_stack state index inside
    control := ?_
    status := ?_
    semantics := rfl
  }
  · simp only [programLookupNativeOrdinaryX87]
    rw [BitVec.extractLsb'_setWidth_of_le (by decide)]
    exact BitVec.extractLsb'_eq_self
  · simp only [programLookupNativeOrdinaryX87]
    rw [BitVec.extractLsb'_setWidth_of_le (by decide)]
    exact BitVec.extractLsb'_eq_self

theorem programLookupNativeOrdinaryX87_preserved_of_x87_eq
    (before after : MachineState)
    (x87Exact : after.x87 = programLookupNativeOrdinaryX87 before) :
    ProgramLookupArchitecturalX87Preserved before after := by
  refine {
    stack := ?_
    control := ?_
    status := ?_
    semantics := ?_
  }
  · intro index inside
    rw [x87Exact]
    exact programLookupNativeOrdinaryX87_stack before index inside
  · rw [x87Exact]
    exact (programLookupNativeOrdinaryX87_preserved before).control
  · rw [x87Exact]
    exact (programLookupNativeOrdinaryX87_preserved before).status
  · rw [x87Exact]
    rfl

private theorem programLookupNativeStep95Result_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 95
      undefinedSlot state).memory = state.memory := by
  by_cases carry : state.eflags.extractLsb' 0 1 = 1#1 <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get,
        StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        conditionExpression, evalFlagBit, carry]

private theorem programLookupNativeStep95Result_esp
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 95
      undefinedSlot state).registers.esp = state.registers.esp := by
  by_cases carry : state.eflags.extractLsb' 0 1 = 1#1 <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get,
        StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        conditionExpression, evalFlagBit, carry]

private theorem programLookupNativeStep95Result_ebp
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 95
      undefinedSlot state).registers.ebp = state.registers.ebp := by
  by_cases carry : state.eflags.extractLsb' 0 1 = 1#1 <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get,
        StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        conditionExpression, evalFlagBit, carry]

private theorem programLookupNativeStep95Result_preserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativePreservedState state
      (programLookupNativeExpectedStepState pe imports environment parameters 95
        undefinedSlot state) := by
  by_cases carry : state.eflags.extractLsb' 0 1 = 1#1
  all_goals
    let after := programLookupNativeExpectedStepState pe imports environment
      parameters 95 undefinedSlot state
    have x87Exact : after.x87 = programLookupNativeOrdinaryX87 state := by
      simp (config := { maxSteps := 1000000 })
        [after, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
          concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
          initialSymbolicX87, Registers.set, Registers.get,
          StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
          StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
          StageA.Formal.applyWrites, conditionExpression, evalFlagBit, carry,
          programLookupNativeOrdinaryX87]
    refine {
      ebx := ?_
      ecx := ?_
      esi := ?_
      edi := ?_
      directionFlag := ?_
      undefinedValue := ?_
      x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state after x87Exact
      x87Physical := ?_
      x87Semantics := ?_
      fsBase := ?_
    } <;>
      simp (config := { maxSteps := 1000000 })
        [after, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
          concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
          initialSymbolicX87, Registers.set, Registers.get,
          StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
          StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
          StageA.Formal.applyWrites, conditionExpression, evalFlagBit, carry]

theorem programLookupNativeGuardResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeGuardResult pe imports environment parameters undefinedSlot
      state).memory = state.memory := by
  unfold programLookupNativeGuardResult
  rw [programLookupNativeStep95Result_memory]
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.subNormalized,
      readOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeGuardResult_esp
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeGuardResult pe imports environment parameters undefinedSlot
      state).registers.esp = state.registers.esp := by
  unfold programLookupNativeGuardResult
  rw [programLookupNativeStep95Result_esp]
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
      readOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeGuardResult_ebp
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeGuardResult pe imports environment parameters undefinedSlot
      state).registers.ebp = state.registers.ebp := by
  unfold programLookupNativeGuardResult
  rw [programLookupNativeStep95Result_ebp]
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
      readOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeGuardResult_preserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativePreservedState state
      (programLookupNativeGuardResult pe imports environment parameters
        undefinedSlot state) := by
  let state92 := programLookupNativeExpectedStepState pe imports environment
    parameters 89 undefinedSlot state
  let state95 := programLookupNativeExpectedStepState pe imports environment
    parameters 92 (undefinedSlot + 1) state92
  have firstX87 : state92.x87 = programLookupNativeOrdinaryX87 state := by
    simp (config := { maxSteps := 1000000 })
      [state92, programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        programLookupNativeOrdinaryX87]
  have first : ProgramLookupNativePreservedState state state92 := by
    refine {
      ebx := ?_
      ecx := ?_
      esi := ?_
      edi := ?_
      directionFlag := ?_
      undefinedValue := ?_
      x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state state92
        firstX87
      x87Physical := ?_
      x87Semantics := ?_
      fsBase := ?_
    } <;>
      simp (config := { maxSteps := 1000000 })
        [state92, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
          SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
          Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
          readOperand32, Addressing.expression, symbolicRead32,
          exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
          programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
          StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
          StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]
  have secondX87 : state95.x87 = programLookupNativeOrdinaryX87 state92 := by
    simp (config := { maxSteps := 1000000 })
      [state95, programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        programLookupNativeOrdinaryX87]
  have second : ProgramLookupNativePreservedState state92 state95 := by
    refine {
      ebx := ?_
      ecx := ?_
      esi := ?_
      edi := ?_
      directionFlag := ?_
      undefinedValue := ?_
      x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state92 state95
        secondX87
      x87Physical := ?_
      x87Semantics := ?_
      fsBase := ?_
    } <;>
      simp (config := { maxSteps := 1000000 })
        [state95, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
          SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
          Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
          readOperand32, Addressing.expression, symbolicRead32,
          exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
          programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
          StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
          StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]
  exact first.trans (second.trans
    (programLookupNativeStep95Result_preserved pe imports environment parameters
      (undefinedSlot + 2) state95))

theorem programLookupNativeLoopLinear_x87
    (edge : ProgramLookupNativeLoopLinearSuccessor offset nextOffset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).x87 = programLookupNativeOrdinaryX87 state := by
  by_cases baseZero : pe.imageBase + parameters.tableRva = 0
  all_goals
    cases edge <;>
      simp (config := { maxSteps := 1000000 })
        [programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?,
          programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
          SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
          initialSymbolicX87, Registers.set, Registers.get,
          Expr.addNormalized, Expr.subNormalized, readOperand32,
          writeOperand32, Addressing.expression, symbolicRead32,
          exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
          programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
          StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
          StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
          programLookupNativeOrdinaryX87, baseZero]

set_option maxHeartbeats 2000000 in
theorem programLookupNativeLoopLinear_machinePreserved
    (edge : ProgramLookupNativeLoopLinearSuccessor offset nextOffset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeExpectedStepState pe imports environment parameters offset
        undefinedSlot state) := by
  let after := programLookupNativeExpectedStepState pe imports environment
    parameters offset undefinedSlot state
  have x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state after
    (programLookupNativeLoopLinear_x87 edge pe imports environment parameters
      undefinedSlot state)
  refine {
    esp := ?_
    ebp := ?_
    preserved := {
      ebx := ?_
      ecx := ?_
      esi := ?_
      edi := ?_
      directionFlag := ?_
      undefinedValue := ?_
      x87
      x87Physical := ?_
      x87Semantics := ?_
      fsBase := ?_
    }
  }
  all_goals
    by_cases baseZero : pe.imageBase + parameters.tableRva = 0
    all_goals
      cases edge <;>
        simp (config := { maxSteps := 1000000 })
          [after, programLookupNativeExpectedStepState,
            stepProgramLookupNativeExpectedInstruction,
            programLookupNativeExpectedDecoded?,
            programLookupNativeExpectedInstruction?,
            stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
            executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
            SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
            initialSymbolicX87, Registers.set, Registers.get,
            Expr.addNormalized, Expr.subNormalized, readOperand32,
            writeOperand32, Addressing.expression, symbolicRead32,
            exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
            programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
            StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
            StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites, baseZero]

theorem programLookupNativeMidpointResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeMidpointResult pe imports environment parameters
        undefinedSlot state) := by
  let state26 := programLookupNativeExpectedStepState pe imports environment
    parameters 23 undefinedSlot state
  let state29 := programLookupNativeExpectedStepState pe imports environment
    parameters 26 (undefinedSlot + 1) state26
  let state31 := programLookupNativeExpectedStepState pe imports environment
    parameters 29 (undefinedSlot + 2) state29
  let state33 := programLookupNativeExpectedStepState pe imports environment
    parameters 31 (undefinedSlot + 3) state31
  let state36 := programLookupNativeExpectedStepState pe imports environment
    parameters 33 (undefinedSlot + 4) state33
  let state38 := programLookupNativeExpectedStepState pe imports environment
    parameters 36 (undefinedSlot + 5) state36
  exact (programLookupNativeLoopLinear_machinePreserved .offset23 pe imports
    environment parameters undefinedSlot state).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset26 pe imports
        environment parameters (undefinedSlot + 1) state26).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset29 pe imports
        environment parameters (undefinedSlot + 2) state29).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset31 pe imports
        environment parameters (undefinedSlot + 3) state31).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset33 pe imports
        environment parameters (undefinedSlot + 4) state33).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset36 pe imports
        environment parameters (undefinedSlot + 5) state36).trans
        (programLookupNativeLoopLinear_machinePreserved .offset38 pe imports
          environment parameters (undefinedSlot + 6) state38))))))

theorem programLookupNativeRecordPreWriteResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeRecordPreWriteResult pe imports environment parameters
        undefinedSlot state) := by
  let state44 := programLookupNativeExpectedStepState pe imports environment
    parameters 41 undefinedSlot state
  let state46 := programLookupNativeExpectedStepState pe imports environment
    parameters 44 (undefinedSlot + 1) state44
  let state49 := programLookupNativeExpectedStepState pe imports environment
    parameters 46 (undefinedSlot + 2) state46
  let state51 := programLookupNativeExpectedStepState pe imports environment
    parameters 49 (undefinedSlot + 3) state49
  let state54 := programLookupNativeExpectedStepState pe imports environment
    parameters 51 (undefinedSlot + 4) state51
  let state59 := programLookupNativeExpectedStepState pe imports environment
    parameters 54 (undefinedSlot + 5) state54
  exact (programLookupNativeLoopLinear_machinePreserved .offset41 pe imports
    environment parameters undefinedSlot state).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset44 pe imports
        environment parameters (undefinedSlot + 1) state44).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset46 pe imports
        environment parameters (undefinedSlot + 2) state46).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset49 pe imports
        environment parameters (undefinedSlot + 3) state49).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset51 pe imports
        environment parameters (undefinedSlot + 4) state51).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset54 pe imports
        environment parameters (undefinedSlot + 5) state54).trans
        (programLookupNativeLoopLinear_machinePreserved .offset59 pe imports
          environment parameters (undefinedSlot + 6) state59))))))

theorem programLookupNativeRecordResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeRecordResult pe imports environment parameters
        undefinedSlot state) := by
  exact (programLookupNativeRecordPreWriteResult_machinePreserved pe imports
    environment parameters undefinedSlot state).trans
      (programLookupNativeLoopLinear_machinePreserved .offset61 pe imports
        environment parameters (undefinedSlot + 7)
          (programLookupNativeRecordPreWriteResult pe imports environment
            parameters undefinedSlot state))

theorem programLookupNativeCompareResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeCompareResult pe imports environment parameters
        undefinedSlot state) := by
  exact (programLookupNativeLoopLinear_machinePreserved .offset64 pe imports
    environment parameters undefinedSlot state).trans
      (programLookupNativeLoopLinear_machinePreserved .offset67 pe imports
        environment parameters (undefinedSlot + 1)
          (programLookupNativeExpectedStepState pe imports environment parameters
            64 undefinedSlot state))

theorem programLookupNativeLowerUpdateResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeLowerUpdateResult pe imports environment parameters
        undefinedSlot state) := by
  let state75 := programLookupNativeExpectedStepState pe imports environment
    parameters 72 undefinedSlot state
  let state78 := programLookupNativeExpectedStepState pe imports environment
    parameters 75 (undefinedSlot + 1) state75
  exact (programLookupNativeLoopLinear_machinePreserved .offset72 pe imports
    environment parameters undefinedSlot state).trans
      ((programLookupNativeLoopLinear_machinePreserved .offset75 pe imports
        environment parameters (undefinedSlot + 1) state75).trans
        (programLookupNativeLoopLinear_machinePreserved .offset78 pe imports
          environment parameters (undefinedSlot + 2) state78))

theorem programLookupNativeUpperUpdateResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeUpperUpdateResult pe imports environment parameters
        state) := by
  exact (programLookupNativeLoopLinear_machinePreserved .offset83 pe imports
    environment parameters 0 state).trans
      (programLookupNativeLoopLinear_machinePreserved .offset86 pe imports
        environment parameters 1
          (programLookupNativeExpectedStepState pe imports environment parameters
            83 0 state))

theorem programLookupNativeStep81_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeExpectedStepState pe imports environment parameters 81
        undefinedSlot state) := by
  let after := programLookupNativeExpectedStepState pe imports environment
    parameters 81 undefinedSlot state
  have x87Exact : after.x87 = programLookupNativeOrdinaryX87 state := by
    simp (config := { maxSteps := 1000000 })
      [after, programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get,
        StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites, programLookupNativeOrdinaryX87]
  refine {
    esp := ?_
    ebp := ?_
    preserved := {
      ebx := ?_
      ecx := ?_
      esi := ?_
      edi := ?_
      directionFlag := ?_
      undefinedValue := ?_
      x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state after x87Exact
      x87Physical := ?_
      x87Semantics := ?_
      fsBase := ?_
    }
  } <;>
    simp (config := { maxSteps := 1000000 })
      [after, programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get,
        StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeStep70_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeExpectedStepState pe imports environment parameters 70
        undefinedSlot state) := by
  by_cases carry : state.eflags.extractLsb' 0 1 = 1#1
  all_goals
    let after := programLookupNativeExpectedStepState pe imports environment
      parameters 70 undefinedSlot state
    have x87Exact : after.x87 = programLookupNativeOrdinaryX87 state := by
      simp (config := { maxSteps := 1000000 })
        [after, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
          concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
          initialSymbolicX87, Registers.set, Registers.get,
          StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
          StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
          StageA.Formal.applyWrites, conditionExpression, evalFlagBit, carry,
          programLookupNativeOrdinaryX87]
    refine {
      esp := ?_
      ebp := ?_
      preserved := {
        ebx := ?_
        ecx := ?_
        esi := ?_
        edi := ?_
        directionFlag := ?_
        undefinedValue := ?_
        x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state after x87Exact
        x87Physical := ?_
        x87Semantics := ?_
        fsBase := ?_
      }
    } <;>
      simp (config := { maxSteps := 1000000 })
        [after, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
          concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
          initialSymbolicX87, Registers.set, Registers.get,
          StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
          StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
          StageA.Formal.applyWrites, conditionExpression, evalFlagBit, carry]

theorem programLookupNativeFinishStep_x87
    (offsetSupported : ProgramLookupNativeFinishOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).x87 = programLookupNativeOrdinaryX87 state := by
  cases offsetSupported <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
        Expr.subNormalized, readOperand32, writeOperand32,
        Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
        programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
        StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites, conditionExpression, evalFlagBit,
        programLookupNativeOrdinaryX87]

set_option maxHeartbeats 2000000 in
theorem programLookupNativeFinishStep_machinePreserved
    (offsetSupported : ProgramLookupNativeFinishOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeExpectedStepState pe imports environment parameters offset
        undefinedSlot state) := by
  let after := programLookupNativeExpectedStepState pe imports environment
    parameters offset undefinedSlot state
  have x87 := programLookupNativeOrdinaryX87_preserved_of_x87_eq state after
    (programLookupNativeFinishStep_x87 offsetSupported pe imports environment
      parameters undefinedSlot state)
  have facts :
      after.registers.esp = state.registers.esp /\
      after.registers.ebp = state.registers.ebp /\
      after.registers.ebx = state.registers.ebx /\
      after.registers.ecx = state.registers.ecx /\
      after.registers.esi = state.registers.esi /\
      after.registers.edi = state.registers.edi /\
      after.eflags.extractLsb' 10 1 = state.eflags.extractLsb' 10 1 /\
      after.undefinedValue = state.undefinedValue /\
      after.x87Physical = state.x87Physical /\
      after.x87Semantics = state.x87Semantics /\
      after.fsBase = state.fsBase := by
    cases offsetSupported <;>
      simp (config := { maxSteps := 1000000 })
        [after, programLookupNativeExpectedStepState,
          stepProgramLookupNativeExpectedInstruction,
          programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
          stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
          nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
          concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
          initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
          Expr.subNormalized, readOperand32, writeOperand32,
          Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
          programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
          StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
          StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
          StageA.Formal.applyWrites, conditionExpression, evalFlagBit]
  rcases facts with ⟨esp, ebp, ebx, ecx, esi, edi, directionFlag,
    undefinedValue,
    x87Physical, x87Semantics, fsBase⟩
  exact {
    esp
    ebp
    preserved := {
      ebx
      ecx
      esi
      edi
      directionFlag
      undefinedValue
      x87
      x87Physical
      x87Semantics
      fsBase
    }
  }

theorem programLookupNativeFinishCountResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeFinishCountResult pe imports environment parameters
        undefinedSlot state) := by
  let state102 := programLookupNativeExpectedStepState pe imports environment
    parameters 97 undefinedSlot state
  exact (programLookupNativeFinishStep_machinePreserved .offset97 pe imports
    environment parameters undefinedSlot state).trans
      (programLookupNativeFinishStep_machinePreserved .offset102 pe imports
        environment parameters (undefinedSlot + 1) state102)

theorem programLookupNativeFinishRecordResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeFinishRecordResult pe imports environment parameters
        undefinedSlot state) := by
  let state110 := programLookupNativeExpectedStepState pe imports environment
    parameters 107 undefinedSlot state
  let state112 := programLookupNativeExpectedStepState pe imports environment
    parameters 110 (undefinedSlot + 1) state110
  let state115 := programLookupNativeExpectedStepState pe imports environment
    parameters 112 (undefinedSlot + 2) state112
  let state117 := programLookupNativeExpectedStepState pe imports environment
    parameters 115 (undefinedSlot + 3) state115
  let state120 := programLookupNativeExpectedStepState pe imports environment
    parameters 117 (undefinedSlot + 4) state117
  let state125 := programLookupNativeExpectedStepState pe imports environment
    parameters 120 (undefinedSlot + 5) state120
  exact (programLookupNativeFinishStep_machinePreserved .offset107 pe imports
    environment parameters undefinedSlot state).trans
      ((programLookupNativeFinishStep_machinePreserved .offset110 pe imports
        environment parameters (undefinedSlot + 1) state110).trans
      ((programLookupNativeFinishStep_machinePreserved .offset112 pe imports
        environment parameters (undefinedSlot + 2) state112).trans
      ((programLookupNativeFinishStep_machinePreserved .offset115 pe imports
        environment parameters (undefinedSlot + 3) state115).trans
      ((programLookupNativeFinishStep_machinePreserved .offset117 pe imports
        environment parameters (undefinedSlot + 4) state117).trans
      ((programLookupNativeFinishStep_machinePreserved .offset120 pe imports
        environment parameters (undefinedSlot + 5) state120).trans
        (programLookupNativeFinishStep_machinePreserved .offset125 pe imports
          environment parameters (undefinedSlot + 6) state125))))))

theorem programLookupNativeFinishPointerResult_machinePreserved
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    ProgramLookupNativeLoopMachinePreserved state
      (programLookupNativeFinishPointerResult pe imports environment parameters
        undefinedSlot state) := by
  let state135 := programLookupNativeExpectedStepState pe imports environment
    parameters 132 undefinedSlot state
  let state137 := programLookupNativeExpectedStepState pe imports environment
    parameters 135 (undefinedSlot + 1) state135
  let state140 := programLookupNativeExpectedStepState pe imports environment
    parameters 137 (undefinedSlot + 2) state137
  let state142 := programLookupNativeExpectedStepState pe imports environment
    parameters 140 (undefinedSlot + 3) state140
  let state145 := programLookupNativeExpectedStepState pe imports environment
    parameters 142 (undefinedSlot + 4) state142
  let state150 := programLookupNativeExpectedStepState pe imports environment
    parameters 145 (undefinedSlot + 5) state145
  exact (programLookupNativeFinishStep_machinePreserved .offset132 pe imports
    environment parameters undefinedSlot state).trans
      ((programLookupNativeFinishStep_machinePreserved .offset135 pe imports
        environment parameters (undefinedSlot + 1) state135).trans
      ((programLookupNativeFinishStep_machinePreserved .offset137 pe imports
        environment parameters (undefinedSlot + 2) state137).trans
      ((programLookupNativeFinishStep_machinePreserved .offset140 pe imports
        environment parameters (undefinedSlot + 3) state140).trans
      ((programLookupNativeFinishStep_machinePreserved .offset142 pe imports
        environment parameters (undefinedSlot + 4) state142).trans
      ((programLookupNativeFinishStep_machinePreserved .offset145 pe imports
        environment parameters (undefinedSlot + 5) state145).trans
        (programLookupNativeFinishStep_machinePreserved .offset150 pe imports
          environment parameters (undefinedSlot + 6) state150))))))

theorem programLookupNativeFinishCountResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeFinishCountResult pe imports environment parameters
      undefinedSlot state).memory = state.memory := by
  unfold programLookupNativeFinishCountResult
  rw [programLookupNativeFinishStep_memory .offset102,
    programLookupNativeFinishStep_memory .offset97]

theorem programLookupNativeFinishRecordResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeFinishRecordResult pe imports environment parameters
      undefinedSlot state).memory = state.memory := by
  unfold programLookupNativeFinishRecordResult
  rw [programLookupNativeFinishStep_memory .offset125,
    programLookupNativeFinishStep_memory .offset120,
    programLookupNativeFinishStep_memory .offset117,
    programLookupNativeFinishStep_memory .offset115,
    programLookupNativeFinishStep_memory .offset112,
    programLookupNativeFinishStep_memory .offset110,
    programLookupNativeFinishStep_memory .offset107]

theorem programLookupNativeFinishPointerResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeFinishPointerResult pe imports environment parameters
      undefinedSlot state).memory = state.memory := by
  unfold programLookupNativeFinishPointerResult
  rw [programLookupNativeFinishStep_memory .offset150,
    programLookupNativeFinishStep_memory .offset145,
    programLookupNativeFinishStep_memory .offset142,
    programLookupNativeFinishStep_memory .offset140,
    programLookupNativeFinishStep_memory .offset137,
    programLookupNativeFinishStep_memory .offset135,
    programLookupNativeFinishStep_memory .offset132]

theorem programLookupNativeCompareResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeCompareResult pe imports environment parameters
      undefinedSlot state).memory = state.memory := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeCompareResult, programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
      readOperand32, writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeStep70_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 70
      undefinedSlot state).memory = state.memory := by
  by_cases carry : state.eflags.extractLsb' 0 1 = 1#1 <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
        concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
        initialSymbolicX87, Registers.set, Registers.get,
        StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        conditionExpression, evalFlagBit, carry]

theorem programLookupNativeStep81_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 81
      undefinedSlot state).memory = state.memory := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]

theorem programLookupNativeLowerUpdateResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeLowerUpdateResult pe imports environment parameters
      undefinedSlot state).memory =
      state.memory.write32
        (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 4))
        (Memory.read32 state.memory
          (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 12)) +
          BitVec.ofNat 32 1) := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeLowerUpdateResult,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      Expr.subNormalized, readOperand32, writeOperand32,
      Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]

theorem programLookupNativeUpperUpdateResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (state : MachineState) :
    (programLookupNativeUpperUpdateResult pe imports environment parameters
      state).memory =
      state.memory.write32
        (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 8))
        (Memory.read32 state.memory
          (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 12))) := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeUpperUpdateResult,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      Expr.subNormalized, readOperand32, writeOperand32,
      Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites]

theorem programLookupNativeRecordResult_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeRecordResult pe imports environment parameters
      undefinedSlot state).registers.eax =
      (programLookupNativeRecordPreWriteResult pe imports environment parameters
        undefinedSlot state).registers.eax := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeRecordResult, programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      readOperand32, writeOperand32, Addressing.expression,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeOneBitConditionalReconstructs (value : BitVec 1) :
    (if value == BitVec.ofNat 1 1 then BitVec.allOnes 1 else 0#1) = value := by
  have valueBound : value.toNat < 2 := by simpa using value.isLt
  by_cases zero : value.toNat = 0
  · have valueZero : value = 0#1 := by
      apply BitVec.eq_of_toNat_eq
      simpa [zero]
    subst value
    decide
  · have one : value.toNat = 1 := by omega
    have valueOne : value = BitVec.ofNat 1 1 := by
      apply BitVec.eq_of_toNat_eq
      simpa [one]
    subst value
    decide

theorem programLookupFlagIs_false_iff_not_true
    (state : MachineState) (bit : Nat) :
    programLookupFlagIs state bit false ↔
      ¬ programLookupFlagIs state bit true := by
  let value := state.eflags.extractLsb' bit 1
  change value = 0#1 ↔ ¬ value = 1#1
  constructor
  · intro zero one
    rw [zero] at one
    exact (by decide : (0#1 : BitVec 1) ≠ 1#1) one
  · intro notOne
    have reconstructed := programLookupNativeOneBitConditionalReconstructs value
    simpa [notOne] using reconstructed.symm

/-- EFLAGS reification performed by every ordinary instruction that leaves the
reviewed symbolic flag expression unchanged. -/
def programLookupNativeInitialFlags (state : MachineState) : Word :=
  (initialSymbolic.flags.map (FlagsExpr.eval state)).getD state.eflags

@[simp] theorem programLookupNativeInitialFlags_cf (state : MachineState) :
    (programLookupNativeInitialFlags state).extractLsb' 0 1 =
      state.eflags.extractLsb' 0 1 := by
  simpa [programLookupNativeInitialFlags, initialSymbolic, evalFlagBit,
    StageA.Formal.BoolExpr.eval] using
    programLookupNativeOneBitConditionalReconstructs
      (state.eflags.extractLsb' 0 1)

@[simp] theorem programLookupNativeInitialFlags_pf (state : MachineState) :
    (programLookupNativeInitialFlags state).extractLsb' 2 1 =
      state.eflags.extractLsb' 2 1 := by
  simpa [programLookupNativeInitialFlags, initialSymbolic, evalFlagBit,
    StageA.Formal.BoolExpr.eval] using
    programLookupNativeOneBitConditionalReconstructs
      (state.eflags.extractLsb' 2 1)

@[simp] theorem programLookupNativeInitialFlags_zf (state : MachineState) :
    (programLookupNativeInitialFlags state).extractLsb' 6 1 =
      state.eflags.extractLsb' 6 1 := by
  simpa [programLookupNativeInitialFlags, initialSymbolic, evalFlagBit,
    StageA.Formal.BoolExpr.eval] using
    programLookupNativeOneBitConditionalReconstructs
      (state.eflags.extractLsb' 6 1)

@[simp] theorem programLookupNativeInitialFlags_sf (state : MachineState) :
    (programLookupNativeInitialFlags state).extractLsb' 7 1 =
      state.eflags.extractLsb' 7 1 := by
  simpa [programLookupNativeInitialFlags, initialSymbolic, evalFlagBit,
    StageA.Formal.BoolExpr.eval] using
    programLookupNativeOneBitConditionalReconstructs
      (state.eflags.extractLsb' 7 1)

@[simp] theorem programLookupNativeInitialFlags_df (state : MachineState) :
    (programLookupNativeInitialFlags state).extractLsb' 10 1 =
      state.eflags.extractLsb' 10 1 := by
  simpa only [programLookupNativeInitialFlags, initialSymbolic] using
    StageA.Formal.FlagsExpr.eval_extract_df state {
      zero := some (.inputFlag 6)
      carry := some (.inputFlag 0)
      sign := some (.inputFlag 7)
      overflow := some (.inputFlag 11)
      parity := some (.inputFlag 2)
    }

@[simp] theorem programLookupNativeInitialFlags_of (state : MachineState) :
    (programLookupNativeInitialFlags state).extractLsb' 11 1 =
      state.eflags.extractLsb' 11 1 := by
  simpa [programLookupNativeInitialFlags, initialSymbolic, evalFlagBit,
    StageA.Formal.BoolExpr.eval] using
    programLookupNativeOneBitConditionalReconstructs
      (state.eflags.extractLsb' 11 1)

def programLookupNativeLeaveResult (state : MachineState) : MachineState := {
  registers := {
    eax := state.registers.eax
    ebx := state.registers.ebx
    ecx := state.registers.ecx
    edx := state.registers.edx
    esi := state.registers.esi
    edi := state.registers.edi
    ebp := Memory.read32 state.memory state.registers.ebp
    esp := state.registers.ebp + BitVec.ofNat 32 4
  }
  memory := state.memory
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeXorEdxResult (undefinedSlot : Nat)
    (state : MachineState) : MachineState := {
  registers := { state.registers with edx := BitVec.ofNat 32 0 }
  memory := state.memory
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := (logicalFlags undefinedSlot (.constant 0)).eval state
  fsBase := state.fsBase
}

def programLookupNativeRetResult (state : MachineState) : MachineState := {
  registers := { state.registers with
    esp := state.registers.esp + BitVec.ofNat 32 4 }
  memory := state.memory
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeEpilogueResult (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeRetResult
    (programLookupNativeXorEdxResult (undefinedSlot + 1)
      (programLookupNativeLeaveResult state))

theorem ProgramLookupNativeInstructionInventory.stepLeaveExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState)
    (events : List NativeExternalEvent) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 157) undefinedSlot state [] 0 events) =
      .running (parameters.entryRva + 158) (undefinedSlot + 1)
        (programLookupNativeLeaveResult state) [] 0 events := by
  rw [inventory.stepNativeAt imports environment 157 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeLeaveResult, programLookupNativeInitialFlags,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      Expr.offset, readOperand32, writeOperand32,
      symbolicRead32, exactWrite32WithDisjointTail?,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87]

theorem ProgramLookupNativeInstructionInventory.stepXorEdxExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState)
    (events : List NativeExternalEvent) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 158) undefinedSlot state [] 0 events) =
      .running (parameters.entryRva + 160) (undefinedSlot + 1)
        (programLookupNativeXorEdxResult undefinedSlot state) [] 0 events := by
  rw [inventory.stepNativeAt imports environment 158 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeXorEdxResult,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.xorNormalized,
      readOperand32, writeOperand32, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      programLookupNativeOrdinaryX87]

theorem ProgramLookupNativeInstructionInventory.stepRetExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState)
    (events : List NativeExternalEvent) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 160) undefinedSlot state [] 0 events) =
      .returned (programLookupNativeRetResult state) events := by
  rw [inventory.stepNativeAt imports environment 160 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeRetResult, programLookupNativeInitialFlags,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, nextNativeExecution,
      executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.offset,
      Expr.addNormalized,
      symbolicRead32, exactWrite32WithDisjointTail?,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87]

/-- Exact execution of the final basic block, independently cacheable from all
lookup-loop proofs. -/
theorem ProgramLookupNativeInstructionInventory.runEpilogueExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) (state : MachineState)
    (events : List NativeExternalEvent) :
    runProgramLookupNativeFuel pe imports environment 3
        (.running (parameters.entryRva + 157) undefinedSlot state [] 0 events) =
      .returned (programLookupNativeEpilogueResult undefinedSlot state) events := by
  rw [runProgramLookupNativeFuel,
    inventory.stepLeaveExact imports environment undefinedSlot]
  rw [runProgramLookupNativeFuel,
    inventory.stepXorEdxExact imports environment (undefinedSlot + 1)]
  rw [runProgramLookupNativeFuel,
    inventory.stepRetExact imports environment (undefinedSlot + 1 + 1)]
  rfl

def programLookupNativePushEbpResult (state : MachineState) : MachineState := {
  registers := { state.registers with
    esp := programLookupStackSub state.registers.esp 4 }
  memory := state.memory.write32 (programLookupStackSub state.registers.esp 4)
    state.registers.ebp
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeSetEbpResult (state : MachineState) : MachineState := {
  registers := { state.registers with ebp := state.registers.esp }
  memory := state.memory
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeReserveFrameResult (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  let left : Expr := .inputReg .esp
  let right : Expr := .constant 16
  let result := Expr.subNormalized left right
  {
    registers := { state.registers with
      esp := programLookupStackSub state.registers.esp 16 }
    memory := state.memory
    undefinedValue := state.undefinedValue
    x87 := programLookupNativeOrdinaryX87 state
    x87Physical := state.x87Physical
    x87Semantics := state.x87Semantics
    eflags := (subtractionFlags left right result).eval state
    fsBase := state.fsBase
  }

def programLookupNativeInitializeLowResult (state : MachineState) : MachineState := {
  registers := state.registers
  memory := state.memory.write32 (programLookupStackSub state.registers.ebp 4)
    (BitVec.ofNat 32 0)
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeLoadCountResult (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) (state : MachineState) :
    MachineState := {
  registers := { state.registers with
    eax := Memory.read32 state.memory
      (BitVec.ofNat 32 (pe.imageBase + parameters.countRva)) }
  memory := state.memory
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeStoreHighResult (state : MachineState) : MachineState := {
  registers := state.registers
  memory := state.memory.write32 (programLookupStackSub state.registers.ebp 8)
    state.registers.eax
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

def programLookupNativeControlResult (state : MachineState) : MachineState := {
  registers := state.registers
  memory := state.memory
  undefinedValue := state.undefinedValue
  x87 := programLookupNativeOrdinaryX87 state
  x87Physical := state.x87Physical
  x87Semantics := state.x87Semantics
  eflags := programLookupNativeInitialFlags state
  fsBase := state.fsBase
}

@[simp] theorem evalZeroAddNormalizedConstant (state : MachineState)
    (value : Nat) :
    Expr.eval state ((Expr.constant 0).addNormalized (Expr.constant value)) =
      BitVec.ofNat 32 value := by
  cases value <;> simp [Expr.addNormalized, Expr.eval]

@[simp] theorem evalZeroBaseDisplacement (state : MachineState)
    (value : Nat) :
    Expr.eval state
        (((Expr.constant 0).addNormalized (Expr.constant 0)).addNormalized
          (Expr.constant value)) =
      BitVec.ofNat 32 value := by
  change Expr.eval state
      ((Expr.constant 0).addNormalized (Expr.constant value)) = _
  exact evalZeroAddNormalizedConstant state value

@[simp] theorem evalInputRegZeroBaseDisplacement (state : MachineState)
    (reg : Reg) (value : Nat) :
    Expr.eval state
        (((Expr.inputReg reg).addNormalized (Expr.constant 0)).addNormalized
          (Expr.constant value)) =
      state.registers.get reg + BitVec.ofNat 32 value := by
  change Expr.eval state
      ((Expr.inputReg reg).addNormalized (Expr.constant value)) = _
  exact evalInputRegAddNormalizedConstant state reg value

def programLookupNativePrologueResult (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) (state : MachineState) :
    MachineState :=
  programLookupNativeControlResult
    (programLookupNativeStoreHighResult
      (programLookupNativeLoadCountResult pe parameters
        (programLookupNativeInitializeLowResult
          (programLookupNativeReserveFrameResult 2
            (programLookupNativeSetEbpResult
              (programLookupNativePushEbpResult state))))))

theorem ProgramLookupNativeInstructionInventory.stepPushEbpExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running parameters.entryRva 0 state [] 0 []) =
      .running (parameters.entryRva + 1) 1
        (programLookupNativePushEbpResult state) [] 0 [] := by
  rw [show parameters.entryRva = parameters.entryRva + 0 by omega]
  rw [inventory.stepNativeAt imports environment 0 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativePushEbpResult, programLookupStackSub,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.offset,
      Expr.addNormalized,
      symbolicRead32, exactWrite32WithDisjointTail?, SymbolicBehavior.write32,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87,
      programLookupNativeInitialFlags]
  all_goals simp only [word_add_ia32_minus_four]

theorem ProgramLookupNativeInstructionInventory.stepSetEbpExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 1) 1 state [] 0 []) =
      .running (parameters.entryRva + 3) 2
        (programLookupNativeSetEbpResult state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 1 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeSetEbpResult,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, readOperand32,
      writeOperand32, StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87,
      programLookupNativeInitialFlags]

theorem ProgramLookupNativeInstructionInventory.stepReserveFrameExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 3) 2 state [] 0 []) =
      .running (parameters.entryRva + 6) 3
        (programLookupNativeReserveFrameResult 2 state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 3 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeReserveFrameResult, programLookupStackSub,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.subNormalized,
      readOperand32, writeOperand32,
      BitVec.sub_eq_add_neg,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87]
  all_goals bv_decide

theorem ProgramLookupNativeInstructionInventory.stepInitializeLowExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 6) 3 state [] 0 []) =
      .running (parameters.entryRva + 13) 4
        (programLookupNativeInitializeLowResult state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 6 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeInitializeLowResult, programLookupStackSub,
      programLookupNativeInitialFlags,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      Expr.offset, readOperand32, writeOperand32, symbolicRead32,
      exactWrite32WithDisjointTail?, SymbolicBehavior.write32,
      Addressing.expression, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      programLookupNativeOrdinaryX87]

theorem ProgramLookupNativeInstructionInventory.stepLoadCountExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 13) 4 state [] 0 []) =
      .running (parameters.entryRva + 18) 5
        (programLookupNativeLoadCountResult pe parameters state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 13 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeLoadCountResult, programLookupNativeInitialFlags,
      programLookupNativeMemoryOperand,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, readOperand32,
      Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87]

theorem ProgramLookupNativeInstructionInventory.stepStoreHighExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 18) 5 state [] 0 []) =
      .running (parameters.entryRva + 21) 6
        (programLookupNativeStoreHighResult state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 18 (by decide)]
  simp (config := { maxSteps := 200000 })
    [programLookupNativeStoreHighResult, programLookupStackSub,
      programLookupNativeInitialFlags,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      Expr.offset, readOperand32, writeOperand32, symbolicRead32,
      exactWrite32WithDisjointTail?, SymbolicBehavior.write32,
      Addressing.expression, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      programLookupNativeOrdinaryX87]

theorem ProgramLookupNativeInstructionInventory.stepJumpToLoopExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) :
    stepNativeExecution pe imports environment
        (.running (parameters.entryRva + 21) 6 state [] 0 []) =
      .running (parameters.entryRva + 89) 0
        (programLookupNativeControlResult state) [] 0 [] := by
  rw [inventory.stepNativeAt imports environment 21 (by decide)]
  have target :
      relativeTarget8 (parameters.entryRva + 23) 66 =
        parameters.entryRva + 89 := by
    exact programLookupRelativeTarget8Forward parameters 23 66 89
      (by omega) (by omega) (by omega)
  simp (config := { maxSteps := 200000 })
    [programLookupNativeControlResult, programLookupNativeInitialFlags,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?,
      programLookupNativeExpectedInstruction?, stepDecodedPE32Instruction,
      continueProgramLookupNativeExecution, nextNativeExecution,
      executeInstructionWithContext, executeInstruction,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, programLookupNativeOrdinaryX87, target,
      Nat.add_assoc]

theorem ProgramLookupNativeInstructionInventory.runPrologueExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (state : MachineState) :
    runProgramLookupNativeFuel pe imports environment 7
        (.running parameters.entryRva 0 state [] 0 []) =
      .running (parameters.entryRva + 89) 0
        (programLookupNativePrologueResult pe parameters state) [] 0 [] := by
  rw [runProgramLookupNativeFuel, inventory.stepPushEbpExact]
  rw [runProgramLookupNativeFuel, inventory.stepSetEbpExact]
  rw [runProgramLookupNativeFuel, inventory.stepReserveFrameExact]
  rw [runProgramLookupNativeFuel, inventory.stepInitializeLowExact]
  rw [runProgramLookupNativeFuel, inventory.stepLoadCountExact]
  rw [runProgramLookupNativeFuel, inventory.stepStoreHighExact]
  rw [runProgramLookupNativeFuel, inventory.stepJumpToLoopExact]
  rfl

theorem programLookupFrameByte_add (stackPointer : Word) (offset byte : Nat) :
    programLookupFrameByte stackPointer offset + BitVec.ofNat 32 byte =
      programLookupFrameByte stackPointer (offset + byte) := by
  simp [programLookupFrameByte, BitVec.add_assoc, ← BitVec.ofNat_add,
    Nat.add_assoc]

theorem programLookupFrameWordsAvoid (stackPointer : Word)
    (leftOffset rightOffset : Nat)
    (leftInside : leftOffset + 4 <= 20)
    (rightInside : rightOffset + 4 <= 20)
    (separated : leftOffset + 4 <= rightOffset \/
      rightOffset + 4 <= leftOffset) :
    Write32AvoidsWord
      (programLookupFrameByte stackPointer leftOffset)
      (programLookupFrameByte stackPointer rightOffset) := by
  intro leftByte leftBefore rightByte rightBefore overlap
  rw [programLookupFrameByte_add, programLookupFrameByte_add] at overlap
  have leftBound : 2 ^ 32 - 20 + (leftOffset + leftByte) < 2 ^ 32 := by
    omega
  have rightBound : 2 ^ 32 - 20 + (rightOffset + rightByte) < 2 ^ 32 := by
    omega
  unfold programLookupFrameByte at overlap
  have constants := congrArg (fun value => value - stackPointer) overlap
  simp only [BitVec.add_comm stackPointer, BitVec.add_sub_cancel] at constants
  have naturals := congrArg BitVec.toNat constants
  simp only [BitVec.toNat_ofNat, Nat.mod_eq_of_lt leftBound,
    Nat.mod_eq_of_lt rightBound] at naturals
  omega

theorem programLookupFrameWriteAvoidsStackSuffixWord
    (stackPointer : Word) (frameOffset suffixOffset : Nat)
    (frameInside : frameOffset + 4 <= 20)
    (suffixInside : suffixOffset + 4 <= 8) :
    Write32AvoidsWord (stackPointer + word32 suffixOffset)
      (programLookupFrameByte stackPointer frameOffset) := by
  intro suffixByte suffixByteBefore frameByte frameByteBefore overlap
  apply programLookupFrameAvoidsStackSuffix stackPointer
    (frameOffset + frameByte) (suffixOffset + suffixByte) (by omega) (by omega)
  simpa [programLookupFrameByte, word32, BitVec.add_assoc,
    ← BitVec.ofNat_add, Nat.add_assoc] using overlap

theorem programLookupFrameWordFits (stackPointer : Word) (offset : Nat)
    (stackHasFrame : 20 <= stackPointer.toNat)
    (inside : offset + 4 <= 20) :
    (programLookupFrameByte stackPointer offset).toNat + 4 <= 2 ^ 32 := by
  have stackBefore : stackPointer.toNat < 2 ^ 32 := by
    simpa using stackPointer.isLt
  have constantBefore : 2 ^ 32 - 20 + offset < 2 ^ 32 := by omega
  simp only [programLookupFrameByte, BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt constantBefore]
  rw [Nat.mod_eq_sub_mod (by omega)]
  rw [Nat.mod_eq_of_lt (by omega)]
  omega

theorem programLookupFrameWriteAgreesOutside (stackPointer : Word)
    (beforeMemory : Memory) (offset : Nat) (value : Word)
    (inside : offset + 4 <= 20) :
    MemoryAgreesOutside (programLookupFrameFootprint stackPointer)
      (beforeMemory.write32 (programLookupFrameByte stackPointer offset) value)
      beforeMemory := by
  apply MemoryAgreesOutside.write32Inside
  intro byte byteBefore
  rw [programLookupFrameByte_add]
  exact ⟨offset + byte, by omega, rfl⟩

@[simp] theorem programLookupSavedFrameAddress (stackPointer : Word) :
    programLookupStackSub stackPointer 4 =
      programLookupSavedEbpSlot stackPointer := by
  simp [programLookupStackSub, programLookupSavedEbpSlot,
    programLookupFrameByte]

@[simp] theorem programLookupLowFrameAddress (stackPointer : Word) :
    programLookupStackSub (programLookupStackSub stackPointer 4) 4 =
      programLookupLowSlot stackPointer := by
  unfold programLookupStackSub programLookupLowSlot programLookupFrameByte
  bv_decide

@[simp] theorem programLookupHighFrameAddress (stackPointer : Word) :
    programLookupStackSub (programLookupStackSub stackPointer 4) 8 =
      programLookupHighSlot stackPointer := by
  unfold programLookupStackSub programLookupHighSlot programLookupFrameByte
  bv_decide

@[simp] theorem programLookupReservedStackAddress (stackPointer : Word) :
    programLookupStackSub (programLookupStackSub stackPointer 4) 16 =
      programLookupStackSub stackPointer 20 := by
  unfold programLookupStackSub
  bv_decide

@[simp] theorem programLookupReservedSavedFrameAddress (stackPointer : Word) :
    programLookupStackSub (programLookupSavedEbpSlot stackPointer) 16 =
      programLookupStackSub stackPointer 20 := by
  unfold programLookupStackSub programLookupSavedEbpSlot programLookupFrameByte
  bv_decide

@[simp] theorem programLookupLowSavedFrameAddress (stackPointer : Word) :
    programLookupSavedEbpSlot (programLookupSavedEbpSlot stackPointer) =
      programLookupLowSlot stackPointer := by
  unfold programLookupSavedEbpSlot programLookupLowSlot programLookupFrameByte
  bv_decide

@[simp] theorem programLookupHighSavedFrameAddress (stackPointer : Word) :
    programLookupStackSub (programLookupSavedEbpSlot stackPointer) 8 =
      programLookupHighSlot stackPointer := by
  unfold programLookupStackSub programLookupSavedEbpSlot programLookupHighSlot
    programLookupFrameByte
  bv_decide

theorem programLookupEpilogueStackAddress (stackPointer : Word) :
    (programLookupStackSub stackPointer 4 + BitVec.ofNat 32 4) +
        BitVec.ofNat 32 4 = stackPointer + BitVec.ofNat 32 4 := by
  unfold programLookupStackSub
  bv_decide

@[simp] theorem programLookupMidpointEbpAddress (stackPointer : Word) :
    programLookupSavedEbpSlot stackPointer + BitVec.ofNat 32 (2 ^ 32 - 12) =
      programLookupMidpointSlot stackPointer := by
  unfold programLookupSavedEbpSlot programLookupMidpointSlot
    programLookupFrameByte
  bv_decide

@[simp] theorem programLookupLowEbpAddress (stackPointer : Word) :
    programLookupSavedEbpSlot stackPointer - BitVec.ofNat 32 4 =
      programLookupLowSlot stackPointer := by
  unfold programLookupSavedEbpSlot programLookupLowSlot programLookupFrameByte
  simp only [BitVec.sub_eq_add_neg]
  bv_decide

@[simp] theorem programLookupLowEbpAddressAdd (stackPointer : Word) :
    programLookupSavedEbpSlot stackPointer + BitVec.ofNat 32 (2 ^ 32 - 4) =
      programLookupLowSlot stackPointer := by
  unfold programLookupSavedEbpSlot programLookupLowSlot programLookupFrameByte
  bv_decide

@[simp] theorem programLookupHighEbpAddress (stackPointer : Word) :
    programLookupSavedEbpSlot stackPointer + BitVec.ofNat 32 (2 ^ 32 - 8) =
      programLookupHighSlot stackPointer := by
  unfold programLookupSavedEbpSlot programLookupHighSlot programLookupFrameByte
  bv_decide

@[simp] theorem programLookupRecordEbpAddress (stackPointer : Word) :
    programLookupSavedEbpSlot stackPointer + BitVec.ofNat 32 (2 ^ 32 - 16) =
      programLookupRecordSlot stackPointer := by
  unfold programLookupSavedEbpSlot programLookupRecordSlot
    programLookupFrameByte
  bv_decide

@[simp] theorem programLookupSourceArgumentEbpAddress (stackPointer : Word) :
    programLookupSavedEbpSlot stackPointer + BitVec.ofNat 32 8 =
      stackPointer + BitVec.ofNat 32 4 := by
  unfold programLookupSavedEbpSlot programLookupFrameByte
  bv_decide

def programLookupNativePrologueMemory (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) (state : MachineState) : Memory :=
  ((state.memory.write32 (programLookupSavedEbpSlot state.registers.esp)
      state.registers.ebp).write32
      (programLookupLowSlot state.registers.esp) (BitVec.ofNat 32 0)).write32
    (programLookupHighSlot state.registers.esp)
    (Memory.read32
      ((state.memory.write32 (programLookupSavedEbpSlot state.registers.esp)
          state.registers.ebp).write32
        (programLookupLowSlot state.registers.esp) (BitVec.ofNat 32 0))
      (BitVec.ofNat 32 (pe.imageBase + parameters.countRva)))

@[simp] theorem programLookupNativePrologueResult_esp
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (state : MachineState) :
    (programLookupNativePrologueResult pe parameters state).registers.esp =
      programLookupStackSub state.registers.esp 20 := by
  simp [programLookupNativePrologueResult, programLookupNativeControlResult,
    programLookupNativeStoreHighResult, programLookupNativeLoadCountResult,
    programLookupNativeInitializeLowResult,
    programLookupNativeReserveFrameResult, programLookupNativeSetEbpResult,
    programLookupNativePushEbpResult]

@[simp] theorem programLookupNativePrologueResult_ebp
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (state : MachineState) :
    (programLookupNativePrologueResult pe parameters state).registers.ebp =
      programLookupStackSub state.registers.esp 4 := by
  simp [programLookupNativePrologueResult, programLookupNativeControlResult,
    programLookupNativeStoreHighResult, programLookupNativeLoadCountResult,
    programLookupNativeInitializeLowResult,
    programLookupNativeReserveFrameResult, programLookupNativeSetEbpResult,
    programLookupNativePushEbpResult]

@[simp] theorem programLookupNativePrologueResult_memory
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (state : MachineState) :
    (programLookupNativePrologueResult pe parameters state).memory =
      programLookupNativePrologueMemory pe parameters state := by
  simp [programLookupNativePrologueResult, programLookupNativeControlResult,
    programLookupNativeStoreHighResult, programLookupNativeLoadCountResult,
    programLookupNativeInitializeLowResult,
    programLookupNativeReserveFrameResult, programLookupNativeSetEbpResult,
    programLookupNativePushEbpResult, programLookupNativePrologueMemory]

theorem programLookupNativePrologueMemory_frame
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (state : MachineState) :
    MemoryAgreesOutside (programLookupFrameFootprint state.registers.esp)
      (programLookupNativePrologueMemory pe parameters state) state.memory := by
  let saved := state.memory.write32
    (programLookupSavedEbpSlot state.registers.esp) state.registers.ebp
  let low := saved.write32 (programLookupLowSlot state.registers.esp)
    (BitVec.ofNat 32 0)
  have savedFrame : MemoryAgreesOutside
      (programLookupFrameFootprint state.registers.esp) saved state.memory := by
    simpa [saved, programLookupSavedEbpSlot] using
      programLookupFrameWriteAgreesOutside state.registers.esp state.memory 16
        state.registers.ebp (by omega)
  have lowFrame : MemoryAgreesOutside
      (programLookupFrameFootprint state.registers.esp) low saved := by
    simpa [low, programLookupLowSlot] using
      programLookupFrameWriteAgreesOutside state.registers.esp saved 12
        (BitVec.ofNat 32 0) (by omega)
  have highFrame : MemoryAgreesOutside
      (programLookupFrameFootprint state.registers.esp)
      (low.write32 (programLookupHighSlot state.registers.esp)
        (Memory.read32 low
          (BitVec.ofNat 32 (pe.imageBase + parameters.countRva)))) low := by
    simpa [programLookupHighSlot] using
      programLookupFrameWriteAgreesOutside state.registers.esp low 8
        (Memory.read32 low
          (BitVec.ofNat 32 (pe.imageBase + parameters.countRva))) (by omega)
  simpa [programLookupNativePrologueMemory, saved, low] using
    savedFrame.trans (lowFrame.trans highFrame)

theorem programLookupNativePrologueResult_preserved
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (state : MachineState) :
    ProgramLookupNativePreservedState state
      (programLookupNativePrologueResult pe parameters state) := by
  let push := programLookupNativePushEbpResult state
  let setEbp := programLookupNativeSetEbpResult push
  let reserve := programLookupNativeReserveFrameResult 2 setEbp
  let low := programLookupNativeInitializeLowResult reserve
  let count := programLookupNativeLoadCountResult pe parameters low
  let high := programLookupNativeStoreHighResult count
  have pushX87 : ProgramLookupArchitecturalX87Preserved state push := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have setEbpX87 : ProgramLookupArchitecturalX87Preserved push setEbp := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have reserveX87 : ProgramLookupArchitecturalX87Preserved setEbp reserve := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have lowX87 : ProgramLookupArchitecturalX87Preserved reserve low := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have countX87 : ProgramLookupArchitecturalX87Preserved low count := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have highX87 : ProgramLookupArchitecturalX87Preserved count high := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have controlX87 : ProgramLookupArchitecturalX87Preserved high
      (programLookupNativeControlResult high) := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  refine {
    ebx := ?_
    ecx := ?_
    esi := ?_
    edi := ?_
    directionFlag := ?_
    undefinedValue := ?_
    x87 := pushX87.trans (setEbpX87.trans (reserveX87.trans
      (lowX87.trans (countX87.trans (highX87.trans controlX87)))))
    x87Physical := ?_
    x87Semantics := ?_
    fsBase := ?_
  } <;>
    simp [programLookupNativePrologueResult, programLookupNativeControlResult,
      high, count, low, reserve, setEbp, push,
      programLookupNativeStoreHighResult, programLookupNativeLoadCountResult,
      programLookupNativeInitializeLowResult,
      programLookupNativeReserveFrameResult, programLookupNativeSetEbpResult,
      programLookupNativePushEbpResult]

/-- The native bridge additionally rules out overlap between the 20-byte stack
frame and the loaded count word.  Table overlap is already excluded by the
summary entry relation. -/
structure ProgramLookupNativeLoadedEntry
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva : Nat)
    (before : MachineState) where
  loaded : ProgramLookupLoadedEntry pe parameters records transferCount
    sourceRva before
  transferCountFits : transferCount < 2 ^ 32
  recordSourcesFit : programLookupRecordSourcesFit records = true
  frameDisjointFromCount : forall frameOffset countOffset,
    frameOffset < 20 -> countOffset < 4 ->
      programLookupFrameByte before.registers.esp frameOffset ≠
        BitVec.ofNat 32 (pe.imageBase + parameters.countRva + countOffset)
  frameDisjointFromTable : forall frameOffset tableIndex tableOffset,
    frameOffset < 20 -> tableIndex < records.length -> tableOffset < 4 ->
      programLookupFrameByte before.registers.esp frameOffset ≠
        programLookupTableAddress pe parameters.tableRva tableIndex +
          BitVec.ofNat 32 tableOffset

theorem ProgramLookupNativeLoadedEntry.countAvoidsFrameWord
    (entry : ProgramLookupNativeLoadedEntry pe parameters records transferCount
      sourceRva before)
    (frameOffset : Nat) (inside : frameOffset + 4 <= 20) :
    Write32AvoidsWord
      (BitVec.ofNat 32 (pe.imageBase + parameters.countRva))
      (programLookupFrameByte before.registers.esp frameOffset) := by
  intro countByte countBefore frameByte frameBefore overlap
  apply entry.frameDisjointFromCount (frameOffset + frameByte) countByte
    (by omega) countBefore
  rw [← programLookupFrameByte_add]
  simpa [← BitVec.ofNat_add, Nat.add_assoc] using overlap.symm

theorem programLookupNativePrologueMemory_savedFramePointer
    (entry : ProgramLookupNativeLoadedEntry pe parameters records transferCount
      sourceRva before) :
    Memory.read32 (programLookupNativePrologueMemory pe parameters before)
        (programLookupSavedEbpSlot before.registers.esp) =
      before.registers.ebp := by
  unfold programLookupNativePrologueMemory
  rw [Memory.read32_write32_of_avoids]
  · rw [Memory.read32_write32_of_avoids]
    · apply Memory.read32_write32_same_of_fits
      simpa [programLookupSavedEbpSlot] using
        programLookupFrameWordFits before.registers.esp 16
          entry.loaded.stackHasFrame (by omega)
    · simpa [programLookupSavedEbpSlot, programLookupLowSlot] using
        programLookupFrameWordsAvoid before.registers.esp 16 12
          (by omega) (by omega) (Or.inr (by omega))
  · simpa [programLookupSavedEbpSlot, programLookupHighSlot] using
      programLookupFrameWordsAvoid before.registers.esp 16 8
        (by omega) (by omega) (Or.inr (by omega))

theorem programLookupNativePrologueMemory_low
    (entry : ProgramLookupNativeLoadedEntry pe parameters records transferCount
      sourceRva before) :
    Memory.read32 (programLookupNativePrologueMemory pe parameters before)
        (programLookupLowSlot before.registers.esp) = BitVec.ofNat 32 0 := by
  unfold programLookupNativePrologueMemory
  rw [Memory.read32_write32_of_avoids]
  · apply Memory.read32_write32_same_of_fits
    simpa [programLookupLowSlot] using
      programLookupFrameWordFits before.registers.esp 12
        entry.loaded.stackHasFrame (by omega)
  · simpa [programLookupLowSlot, programLookupHighSlot] using
      programLookupFrameWordsAvoid before.registers.esp 12 8
        (by omega) (by omega) (Or.inr (by omega))

theorem programLookupNativePrologueMemory_high
    (entry : ProgramLookupNativeLoadedEntry pe parameters records transferCount
      sourceRva before) :
    Memory.read32 (programLookupNativePrologueMemory pe parameters before)
        (programLookupHighSlot before.registers.esp) =
      Memory.read32 before.memory
        (BitVec.ofNat 32 (pe.imageBase + parameters.countRva)) := by
  unfold programLookupNativePrologueMemory
  rw [Memory.read32_write32_same_of_fits]
  · rw [Memory.read32_write32_of_avoids]
    · rw [Memory.read32_write32_of_avoids]
      simpa [programLookupSavedEbpSlot] using
        entry.countAvoidsFrameWord 16 (by omega)
    · simpa [programLookupLowSlot] using
        entry.countAvoidsFrameWord 12 (by omega)
  · simpa [programLookupHighSlot] using
      programLookupFrameWordFits before.registers.esp 8
        entry.loaded.stackHasFrame (by omega)

/-- Concrete loop-head state at relative offset 89.  These fields expose every
persistent frame slot and retain the PE-backed loads needed by later chunks. -/
structure ProgramLookupNativeLoopCutpoint
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high : Nat)
    (before state : MachineState) : Prop where
  bounds : low <= high /\ high <= transferCount
  transferCountExact : transferCount = records.length
  sourceFits : sourceRva < 2 ^ 32
  transferCountFits : transferCount < 2 ^ 32
  recordSourcesFit : programLookupRecordSourcesFit records = true
  stackHasFrame : 20 <= before.registers.esp.toNat
  stackPointerExact : state.registers.esp =
    programLookupStackSub before.registers.esp 20
  framePointerExact : state.registers.ebp =
    programLookupStackSub before.registers.esp 4
  savedFramePointer : Memory.read32 state.memory
    (programLookupSavedEbpSlot before.registers.esp) = before.registers.ebp
  returnAddressPreserved : Memory.read32 state.memory before.registers.esp =
    Memory.read32 before.memory before.registers.esp
  sourceArgumentPreserved : Memory.read32 state.memory
    (before.registers.esp + BitVec.ofNat 32 4) = BitVec.ofNat 32 sourceRva
  lowSlotExact : Memory.read32 state.memory
    (programLookupLowSlot before.registers.esp) = BitVec.ofNat 32 low
  highSlotExact : Memory.read32 state.memory
    (programLookupHighSlot before.registers.esp) = BitVec.ofNat 32 high
  countLoaded : Memory.read32 state.memory
    (BitVec.ofNat 32 (pe.imageBase + parameters.countRva)) =
      BitVec.ofNat 32 transferCount
  tableLoaded : forall index record,
    listAt? records index = some record ->
      Memory.read32 state.memory
        (programLookupTableAddress pe parameters.tableRva index) =
          BitVec.ofNat 32 record.sourceRva
  frameDisjointFromCount : forall frameOffset countOffset,
    frameOffset < 20 -> countOffset < 4 ->
      programLookupFrameByte before.registers.esp frameOffset ≠
        BitVec.ofNat 32 (pe.imageBase + parameters.countRva + countOffset)
  frameDisjointFromTable : forall frameOffset tableIndex tableOffset,
    frameOffset < 20 -> tableIndex < records.length -> tableOffset < 4 ->
      programLookupFrameByte before.registers.esp frameOffset ≠
        programLookupTableAddress pe parameters.tableRva tableIndex +
          BitVec.ofNat 32 tableOffset
  memoryFrame : MemoryAgreesOutside
    (programLookupFrameFootprint before.registers.esp)
    state.memory before.memory
  preserved : ProgramLookupNativePreservedState before state

/-- State immediately before `leave; xor edx,edx; ret`. -/
structure ProgramLookupNativeEpilogueCutpoint
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (sourceRva : Nat)
    (before state : MachineState) : Prop where
  stackPointerExact : state.registers.esp =
    programLookupStackSub before.registers.esp 20
  framePointerExact : state.registers.ebp =
    programLookupStackSub before.registers.esp 4
  savedFramePointer : Memory.read32 state.memory
    (programLookupSavedEbpSlot before.registers.esp) = before.registers.ebp
  returnAddressPreserved : Memory.read32 state.memory before.registers.esp =
    Memory.read32 before.memory before.registers.esp
  eaxExact : state.registers.eax =
    programLookupReturnWord pe parameters.tableRva records sourceRva
  memoryFrame : MemoryAgreesOutside
    (programLookupFrameFootprint before.registers.esp)
    state.memory before.memory
  preserved : ProgramLookupNativePreservedState before state

theorem ProgramLookupNativeLoopCutpoint.tableAvoidsFrameWord
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (index offset : Nat) (indexBefore : index < records.length)
    (inside : offset + 4 <= 20) :
    Write32AvoidsWord (programLookupTableAddress pe parameters.tableRva index)
      (programLookupFrameByte before.registers.esp offset) := by
  intro tableByte tableByteBefore frameByte frameByteBefore overlap
  apply cutpoint.frameDisjointFromTable (offset + frameByte) index tableByte
    (by omega) indexBefore tableByteBefore
  rw [programLookupFrameByte_add] at overlap
  exact overlap.symm

theorem ProgramLookupNativeLoopCutpoint.countAvoidsFrameWord
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (offset : Nat) (inside : offset + 4 <= 20) :
    Write32AvoidsWord
      (BitVec.ofNat 32 (pe.imageBase + parameters.countRva))
      (programLookupFrameByte before.registers.esp offset) := by
  intro countByte countByteBefore frameByte frameByteBefore overlap
  apply cutpoint.frameDisjointFromCount (offset + frameByte) countByte
    (by omega) countByteBefore
  simpa [programLookupFrameByte, BitVec.add_assoc, ← BitVec.ofNat_add,
    Nat.add_assoc] using overlap.symm

/-- Lift an instruction cluster which changes no memory back to the authoritative
loop cutpoint.  Register and x87 preservation are carried by the checked machine
witness rather than reproved for each cluster. -/
theorem ProgramLookupNativeLoopCutpoint.afterMemoryPreserved
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (machine : ProgramLookupNativeLoopMachinePreserved state after)
    (memoryExact : after.memory = state.memory) :
    ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
      low high before after := by
  refine {
    bounds := cutpoint.bounds
    transferCountExact := cutpoint.transferCountExact
    sourceFits := cutpoint.sourceFits
    transferCountFits := cutpoint.transferCountFits
    recordSourcesFit := cutpoint.recordSourcesFit
    stackHasFrame := cutpoint.stackHasFrame
    stackPointerExact := machine.esp.trans cutpoint.stackPointerExact
    framePointerExact := machine.ebp.trans cutpoint.framePointerExact
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    sourceArgumentPreserved := ?_
    lowSlotExact := ?_
    highSlotExact := ?_
    countLoaded := ?_
    tableLoaded := ?_
    frameDisjointFromCount := cutpoint.frameDisjointFromCount
    frameDisjointFromTable := cutpoint.frameDisjointFromTable
    memoryFrame := ?_
    preserved := cutpoint.preserved.trans machine.preserved
  }
  · simpa [memoryExact] using cutpoint.savedFramePointer
  · simpa [memoryExact] using cutpoint.returnAddressPreserved
  · simpa [memoryExact] using cutpoint.sourceArgumentPreserved
  · simpa [memoryExact] using cutpoint.lowSlotExact
  · simpa [memoryExact] using cutpoint.highSlotExact
  · simpa [memoryExact] using cutpoint.countLoaded
  · intro index record recordAt
    simpa [memoryExact] using cutpoint.tableLoaded index record recordAt
  · simpa [memoryExact] using cutpoint.memoryFrame

/-- Lift a write to an untracked local scratch word while preserving all loop
facts.  The caller supplies only the three tracked-frame disjointness facts. -/
theorem ProgramLookupNativeLoopCutpoint.afterScratchWrite
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (offset : Nat) (inside : offset + 4 <= 20) (value : Word)
    (machine : ProgramLookupNativeLoopMachinePreserved state after)
    (memoryExact : after.memory = state.memory.write32
      (programLookupFrameByte before.registers.esp offset) value)
    (savedAvoids : Write32AvoidsWord
      (programLookupSavedEbpSlot before.registers.esp)
      (programLookupFrameByte before.registers.esp offset))
    (lowAvoids : Write32AvoidsWord
      (programLookupLowSlot before.registers.esp)
      (programLookupFrameByte before.registers.esp offset))
    (highAvoids : Write32AvoidsWord
      (programLookupHighSlot before.registers.esp)
      (programLookupFrameByte before.registers.esp offset)) :
    ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
      low high before after := by
  refine {
    bounds := cutpoint.bounds
    transferCountExact := cutpoint.transferCountExact
    sourceFits := cutpoint.sourceFits
    transferCountFits := cutpoint.transferCountFits
    recordSourcesFit := cutpoint.recordSourcesFit
    stackHasFrame := cutpoint.stackHasFrame
    stackPointerExact := machine.esp.trans cutpoint.stackPointerExact
    framePointerExact := machine.ebp.trans cutpoint.framePointerExact
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    sourceArgumentPreserved := ?_
    lowSlotExact := ?_
    highSlotExact := ?_
    countLoaded := ?_
    tableLoaded := ?_
    frameDisjointFromCount := cutpoint.frameDisjointFromCount
    frameDisjointFromTable := cutpoint.frameDisjointFromTable
    memoryFrame := ?_
    preserved := cutpoint.preserved.trans machine.preserved
  }
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.savedFramePointer
    exact savedAvoids
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.returnAddressPreserved
    simpa [word32] using
      programLookupFrameWriteAvoidsStackSuffixWord before.registers.esp offset 0
        inside (by omega)
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.sourceArgumentPreserved
    exact programLookupFrameWriteAvoidsStackSuffixWord before.registers.esp offset 4
      inside (by omega)
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.lowSlotExact
    exact lowAvoids
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.highSlotExact
    exact highAvoids
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.countLoaded
    exact cutpoint.countAvoidsFrameWord offset inside
  · intro index record recordAt
    have indexBefore : index < records.length :=
      List.getElem?_eq_some_iff.mp
        (listAt?_eq_some_to_getElem?_eq_some records index record recordAt) |>.1
    rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.tableLoaded index record recordAt
    exact cutpoint.tableAvoidsFrameWord index offset indexBefore inside
  · rw [memoryExact]
    exact cutpoint.memoryFrame.trans
      (programLookupFrameWriteAgreesOutside before.registers.esp state.memory
        offset value inside)

/-- Update the lower bound word and re-establish the loop cutpoint. -/
theorem ProgramLookupNativeLoopCutpoint.afterLowWrite
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (nextLow : Nat) (nextBounds : nextLow <= high)
    (machine : ProgramLookupNativeLoopMachinePreserved state after)
    (memoryExact : after.memory = state.memory.write32
      (programLookupLowSlot before.registers.esp) (BitVec.ofNat 32 nextLow)) :
    ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
      nextLow high before after := by
  refine {
    bounds := ⟨nextBounds, cutpoint.bounds.2⟩
    transferCountExact := cutpoint.transferCountExact
    sourceFits := cutpoint.sourceFits
    transferCountFits := cutpoint.transferCountFits
    recordSourcesFit := cutpoint.recordSourcesFit
    stackHasFrame := cutpoint.stackHasFrame
    stackPointerExact := machine.esp.trans cutpoint.stackPointerExact
    framePointerExact := machine.ebp.trans cutpoint.framePointerExact
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    sourceArgumentPreserved := ?_
    lowSlotExact := ?_
    highSlotExact := ?_
    countLoaded := ?_
    tableLoaded := ?_
    frameDisjointFromCount := cutpoint.frameDisjointFromCount
    frameDisjointFromTable := cutpoint.frameDisjointFromTable
    memoryFrame := ?_
    preserved := cutpoint.preserved.trans machine.preserved
  }
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.savedFramePointer
    simpa [programLookupSavedEbpSlot, programLookupLowSlot] using
      programLookupFrameWordsAvoid before.registers.esp 16 12
        (by omega) (by omega) (Or.inr (by omega))
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.returnAddressPreserved
    simpa [word32] using
      (programLookupFrameWriteAvoidsStackSuffixWord before.registers.esp 12 0
        (by omega) (by omega))
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.sourceArgumentPreserved
    simpa [programLookupLowSlot] using
      programLookupFrameWriteAvoidsStackSuffixWord before.registers.esp 12 4
        (by omega) (by omega)
  · rw [memoryExact, Memory.read32_write32_same_of_fits]
    simpa [programLookupLowSlot] using
      programLookupFrameWordFits before.registers.esp 12 cutpoint.stackHasFrame
        (by omega)
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.highSlotExact
    simpa [programLookupHighSlot, programLookupLowSlot] using
      programLookupFrameWordsAvoid before.registers.esp 8 12
        (by omega) (by omega) (Or.inl (by omega))
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.countLoaded
    simpa [programLookupLowSlot] using cutpoint.countAvoidsFrameWord 12 (by omega)
  · intro index record recordAt
    have indexBefore : index < records.length :=
      List.getElem?_eq_some_iff.mp
        (listAt?_eq_some_to_getElem?_eq_some records index record recordAt) |>.1
    rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.tableLoaded index record recordAt
    simpa [programLookupLowSlot] using
      cutpoint.tableAvoidsFrameWord index 12 indexBefore (by omega)
  · rw [memoryExact]
    apply cutpoint.memoryFrame.trans
    simpa [programLookupLowSlot] using
      (programLookupFrameWriteAgreesOutside before.registers.esp state.memory 12
        (BitVec.ofNat 32 nextLow) (by omega))

/-- Update the upper bound word and re-establish the loop cutpoint. -/
theorem ProgramLookupNativeLoopCutpoint.afterHighWrite
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (nextHigh : Nat) (nextBounds : low <= nextHigh)
    (nextWithinTransfer : nextHigh <= transferCount)
    (machine : ProgramLookupNativeLoopMachinePreserved state after)
    (memoryExact : after.memory = state.memory.write32
      (programLookupHighSlot before.registers.esp) (BitVec.ofNat 32 nextHigh)) :
    ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
      low nextHigh before after := by
  refine {
    bounds := ⟨nextBounds, nextWithinTransfer⟩
    transferCountExact := cutpoint.transferCountExact
    sourceFits := cutpoint.sourceFits
    transferCountFits := cutpoint.transferCountFits
    recordSourcesFit := cutpoint.recordSourcesFit
    stackHasFrame := cutpoint.stackHasFrame
    stackPointerExact := machine.esp.trans cutpoint.stackPointerExact
    framePointerExact := machine.ebp.trans cutpoint.framePointerExact
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    sourceArgumentPreserved := ?_
    lowSlotExact := ?_
    highSlotExact := ?_
    countLoaded := ?_
    tableLoaded := ?_
    frameDisjointFromCount := cutpoint.frameDisjointFromCount
    frameDisjointFromTable := cutpoint.frameDisjointFromTable
    memoryFrame := ?_
    preserved := cutpoint.preserved.trans machine.preserved
  }
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.savedFramePointer
    simpa [programLookupSavedEbpSlot, programLookupHighSlot] using
      programLookupFrameWordsAvoid before.registers.esp 16 8
        (by omega) (by omega) (Or.inr (by omega))
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.returnAddressPreserved
    simpa [word32] using
      (programLookupFrameWriteAvoidsStackSuffixWord before.registers.esp 8 0
        (by omega) (by omega))
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.sourceArgumentPreserved
    simpa [programLookupHighSlot] using
      programLookupFrameWriteAvoidsStackSuffixWord before.registers.esp 8 4
        (by omega) (by omega)
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.lowSlotExact
    simpa [programLookupLowSlot, programLookupHighSlot] using
      programLookupFrameWordsAvoid before.registers.esp 12 8
        (by omega) (by omega) (Or.inr (by omega))
  · rw [memoryExact, Memory.read32_write32_same_of_fits]
    simpa [programLookupHighSlot] using
      programLookupFrameWordFits before.registers.esp 8 cutpoint.stackHasFrame
        (by omega)
  · rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.countLoaded
    simpa [programLookupHighSlot] using cutpoint.countAvoidsFrameWord 8 (by omega)
  · intro index record recordAt
    have indexBefore : index < records.length :=
      List.getElem?_eq_some_iff.mp
        (listAt?_eq_some_to_getElem?_eq_some records index record recordAt) |>.1
    rw [memoryExact, Memory.read32_write32_of_avoids]
    exact cutpoint.tableLoaded index record recordAt
    simpa [programLookupHighSlot] using
      cutpoint.tableAvoidsFrameWord index 8 indexBefore (by omega)
  · rw [memoryExact]
    apply cutpoint.memoryFrame.trans
    simpa [programLookupHighSlot] using
      (programLookupFrameWriteAgreesOutside before.registers.esp state.memory 8
        (BitVec.ofNat 32 nextHigh) (by omega))

theorem ProgramLookupNativeLoopCutpoint.toEpilogueCutpoint
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (machine : ProgramLookupNativeLoopMachinePreserved state after)
    (memoryExact : after.memory = state.memory)
    (eaxExact : after.registers.eax =
      programLookupReturnWord pe parameters.tableRva records sourceRva) :
    ProgramLookupNativeEpilogueCutpoint pe parameters records sourceRva before
      after := by
  refine {
    stackPointerExact := machine.esp.trans cutpoint.stackPointerExact
    framePointerExact := machine.ebp.trans cutpoint.framePointerExact
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    eaxExact
    memoryFrame := ?_
    preserved := cutpoint.preserved.trans machine.preserved
  }
  · simpa [memoryExact] using cutpoint.savedFramePointer
  · simpa [memoryExact] using cutpoint.returnAddressPreserved
  · simpa [memoryExact] using cutpoint.memoryFrame

theorem programLookupNativeMidpointResult_memory
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high midpoint undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (midpointExact : midpoint = low + (high - low) / 2) :
    (programLookupNativeMidpointResult pe imports environment parameters
      undefinedSlot state).memory =
      state.memory.write32 (programLookupMidpointSlot before.registers.esp)
        (BitVec.ofNat 32 midpoint) := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeMidpointResult, programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, SymbolicBehavior.write32, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, Expr.addNormalized,
      Expr.subNormalized, readOperand32, writeOperand32,
      Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
      programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
      StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      cutpoint.framePointerExact]
  rw [programLookupHighEbpAddress, cutpoint.lowSlotExact,
    cutpoint.highSlotExact, programLookupMidpointEbpAddress]
  rw [programLookupMidpointWord low high midpoint cutpoint.bounds.1
    (Nat.lt_of_le_of_lt cutpoint.bounds.2 cutpoint.transferCountFits)
    midpointExact]

theorem ProgramLookupNativeInstructionInventory.runLoopGuardTakenExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (notConverged : low < high) :
    runProgramLookupNativeFuel pe imports environment 3
        (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 23) 0
        (programLookupNativeGuardResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  let state92 := programLookupNativeExpectedStepState pe imports environment
    parameters 89 undefinedSlot state
  let state95 := programLookupNativeExpectedStepState pe imports environment
    parameters 92 (undefinedSlot + 1) state92
  have step92Shape :
      stepProgramLookupNativeExpectedInstruction pe imports environment parameters
          92 (undefinedSlot + 1) state92 [] 0 [] =
        .running (parameters.entryRva + 95) (undefinedSlot + 2) state95 [] 0 [] := by
    simp (config := { maxSteps := 1000000 })
      [state92, state95, programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]
  have lowFits : low < 2 ^ 32 :=
    Nat.lt_of_le_of_lt cutpoint.bounds.1
      (Nat.lt_of_le_of_lt cutpoint.bounds.2 cutpoint.transferCountFits)
  have highFits : high < 2 ^ 32 :=
    Nat.lt_of_le_of_lt cutpoint.bounds.2 cutpoint.transferCountFits
  have highExactRaw : Memory.read32 state.memory
      (programLookupSavedEbpSlot before.registers.esp +
        BitVec.ofNat 32 (2 ^ 32 - 8)) = BitVec.ofNat 32 high := by
    rw [programLookupHighEbpAddress]
    exact cutpoint.highSlotExact
  have carry : programLookupFlagIs state95 0 true := by
    simp (config := { maxSteps := 1000000 })
      [state92, state95, programLookupFlagIs,
        programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.applyWrites, evalFlagBit,
        subtractionFlags, cutpoint.framePointerExact, cutpoint.lowSlotExact,
        programLookupHighEbpAddress, cutpoint.highSlotExact, highExactRaw,
        BitVec.ult_iff_lt, BitVec.toNat_ofNat,
        Nat.mod_eq_of_lt lowFits, Nat.mod_eq_of_lt highFits, notConverged]
  rw [runProgramLookupNativeFuel,
    inventory.step89Exact imports environment undefinedSlot]
  rw [runProgramLookupNativeFuel,
    inventory.stepNativeAt imports environment 92 (by decide)]
  rw [step92Shape]
  rw [runProgramLookupNativeFuel,
    inventory.stepNativeAt imports environment 95 (by decide)]
  rw [programLookupNativeStep95Taken pe imports environment parameters
    (undefinedSlot + 2) state95 carry]
  simp [programLookupNativeGuardResult, state92, state95,
    runProgramLookupNativeFuel]

theorem ProgramLookupNativeInstructionInventory.runLoopGuardExitExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva index undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva index index before state) :
    runProgramLookupNativeFuel pe imports environment 3
        (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 97) 0
        (programLookupNativeGuardResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  let state92 := programLookupNativeExpectedStepState pe imports environment
    parameters 89 undefinedSlot state
  let state95 := programLookupNativeExpectedStepState pe imports environment
    parameters 92 (undefinedSlot + 1) state92
  have step92Shape :
      stepProgramLookupNativeExpectedInstruction pe imports environment parameters
          92 (undefinedSlot + 1) state92 [] 0 [] =
        .running (parameters.entryRva + 95) (undefinedSlot + 2) state95 [] 0 [] := by
    simp (config := { maxSteps := 1000000 })
      [state92, state95, programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]
  have indexFits : index < 2 ^ 32 :=
    Nat.lt_of_le_of_lt cutpoint.bounds.2 cutpoint.transferCountFits
  have highExactRaw : Memory.read32 state.memory
      (programLookupSavedEbpSlot before.registers.esp +
        BitVec.ofNat 32 (2 ^ 32 - 8)) = BitVec.ofNat 32 index := by
    rw [programLookupHighEbpAddress]
    exact cutpoint.highSlotExact
  have noCarry : programLookupFlagIs state95 0 false := by
    simp (config := { maxSteps := 1000000 })
      [state92, state95, programLookupFlagIs,
        programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
        readOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.applyWrites, evalFlagBit,
        subtractionFlags, cutpoint.framePointerExact, cutpoint.lowSlotExact,
        programLookupHighEbpAddress, cutpoint.highSlotExact, highExactRaw,
        BitVec.ult_iff_lt, BitVec.toNat_ofNat, Nat.mod_eq_of_lt indexFits]
  rw [runProgramLookupNativeFuel,
    inventory.step89Exact imports environment undefinedSlot]
  rw [runProgramLookupNativeFuel,
    inventory.stepNativeAt imports environment 92 (by decide)]
  rw [step92Shape]
  rw [runProgramLookupNativeFuel,
    inventory.stepNativeAt imports environment 95 (by decide)]
  rw [programLookupNativeStep95Exit pe imports environment parameters
    (undefinedSlot + 2) state95 noCarry]
  simp [programLookupNativeGuardResult, state92, state95,
    runProgramLookupNativeFuel]

theorem ProgramLookupNativeLoopCutpoint.afterGuard
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (imports : List PEImport) (environment : NativeEnvironment)
    (undefinedSlot : Nat) :
    ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
      low high before
      (programLookupNativeGuardResult pe imports environment parameters
        undefinedSlot state) := by
  let after := programLookupNativeGuardResult pe imports environment parameters
    undefinedSlot state
  have memoryExact : after.memory = state.memory :=
    programLookupNativeGuardResult_memory pe imports environment parameters
      undefinedSlot state
  have espExact : after.registers.esp = state.registers.esp :=
    programLookupNativeGuardResult_esp pe imports environment parameters
      undefinedSlot state
  have ebpExact : after.registers.ebp = state.registers.ebp :=
    programLookupNativeGuardResult_ebp pe imports environment parameters
      undefinedSlot state
  refine {
    bounds := cutpoint.bounds
    transferCountExact := cutpoint.transferCountExact
    sourceFits := cutpoint.sourceFits
    transferCountFits := cutpoint.transferCountFits
    recordSourcesFit := cutpoint.recordSourcesFit
    stackHasFrame := cutpoint.stackHasFrame
    stackPointerExact := ?_
    framePointerExact := ?_
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    sourceArgumentPreserved := ?_
    lowSlotExact := ?_
    highSlotExact := ?_
    countLoaded := ?_
    tableLoaded := ?_
    frameDisjointFromCount := cutpoint.frameDisjointFromCount
    frameDisjointFromTable := cutpoint.frameDisjointFromTable
    memoryFrame := ?_
    preserved := cutpoint.preserved.trans
      (programLookupNativeGuardResult_preserved pe imports environment parameters
        undefinedSlot state)
  }
  · exact espExact.trans cutpoint.stackPointerExact
  · exact ebpExact.trans cutpoint.framePointerExact
  · rw [memoryExact]
    exact cutpoint.savedFramePointer
  · rw [memoryExact]
    exact cutpoint.returnAddressPreserved
  · rw [memoryExact]
    exact cutpoint.sourceArgumentPreserved
  · rw [memoryExact]
    exact cutpoint.lowSlotExact
  · rw [memoryExact]
    exact cutpoint.highSlotExact
  · rw [memoryExact]
    exact cutpoint.countLoaded
  · intro index record recordAt
    rw [memoryExact]
    exact cutpoint.tableLoaded index record recordAt
  · rw [memoryExact]
    exact cutpoint.memoryFrame

theorem programLookupNativeCompareResult_carry_iff
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot sourceRva : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (framePointerExact : state.registers.ebp =
      programLookupSavedEbpSlot before.registers.esp)
    (recordExact : Memory.read32 state.memory
      (programLookupRecordSlot before.registers.esp) =
        BitVec.ofNat 32 record.sourceRva)
    (sourceExact : Memory.read32 state.memory
      (before.registers.esp + BitVec.ofNat 32 4) = BitVec.ofNat 32 sourceRva)
    (recordFits : record.sourceRva < 2 ^ 32)
    (sourceFits : sourceRva < 2 ^ 32) :
    programLookupFlagIs
      (programLookupNativeCompareResult pe imports environment parameters
        undefinedSlot state) 0 true ↔ record.sourceRva < sourceRva := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeCompareResult, programLookupFlagIs,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
      readOperand32, writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.applyWrites, evalFlagBit,
      subtractionFlags, framePointerExact, programLookupRecordEbpAddress,
      recordExact, programLookupSourceArgumentEbpAddress, sourceExact,
      BitVec.ult_iff_lt, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt recordFits, Nat.mod_eq_of_lt sourceFits]
  rw [programLookupRecordEbpAddress, recordExact]
  simp [BitVec.ult_iff_lt, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt recordFits, Nat.mod_eq_of_lt sourceFits]

theorem programLookupNativeCompareResult_noCarry_iff
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot sourceRva : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (framePointerExact : state.registers.ebp =
      programLookupSavedEbpSlot before.registers.esp)
    (recordExact : Memory.read32 state.memory
      (programLookupRecordSlot before.registers.esp) =
        BitVec.ofNat 32 record.sourceRva)
    (sourceExact : Memory.read32 state.memory
      (before.registers.esp + BitVec.ofNat 32 4) = BitVec.ofNat 32 sourceRva)
    (recordFits : record.sourceRva < 2 ^ 32)
    (sourceFits : sourceRva < 2 ^ 32) :
    programLookupFlagIs
      (programLookupNativeCompareResult pe imports environment parameters
        undefinedSlot state) 0 false ↔ ¬ record.sourceRva < sourceRva := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeCompareResult, programLookupFlagIs,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, Expr.subNormalized,
      readOperand32, writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.applyWrites, evalFlagBit,
      subtractionFlags, framePointerExact, programLookupRecordEbpAddress,
      recordExact, programLookupSourceArgumentEbpAddress, sourceExact,
      BitVec.ult_iff_lt, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt recordFits, Nat.mod_eq_of_lt sourceFits]
  rw [programLookupRecordEbpAddress, recordExact]
  simp [BitVec.ult_iff_lt, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt recordFits, Nat.mod_eq_of_lt sourceFits]

theorem programLookupNativeFinishCountResult_carry_iff
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva index undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva index index before state) :
    programLookupFlagIs
        (programLookupNativeFinishCountResult pe imports environment parameters
          undefinedSlot state) 0 true ↔ index < transferCount := by
  have indexFits : index < 2 ^ 32 :=
    Nat.lt_of_le_of_lt cutpoint.bounds.2 cutpoint.transferCountFits
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeFinishCountResult, programLookupFlagIs,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.subNormalized,
      readOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.applyWrites, evalFlagBit,
      subtractionFlags, cutpoint.framePointerExact, programLookupSavedFrameAddress,
      programLookupLowEbpAddressAdd, cutpoint.lowSlotExact, cutpoint.countLoaded,
      BitVec.ult_iff_lt, BitVec.toNat_ofNat, Nat.mod_eq_of_lt indexFits,
      Nat.mod_eq_of_lt cutpoint.transferCountFits]

inductive ProgramLookupNativeFinishLowLoadOffset : Nat -> Prop
  | offset107 : ProgramLookupNativeFinishLowLoadOffset 107
  | offset132 : ProgramLookupNativeFinishLowLoadOffset 132

inductive ProgramLookupNativeFinishMoveIndexOffset : Nat -> Prop
  | offset110 : ProgramLookupNativeFinishMoveIndexOffset 110
  | offset135 : ProgramLookupNativeFinishMoveIndexOffset 135

inductive ProgramLookupNativeFinishScaleFourOffset : Nat -> Prop
  | offset112 : ProgramLookupNativeFinishScaleFourOffset 112
  | offset137 : ProgramLookupNativeFinishScaleFourOffset 137

inductive ProgramLookupNativeFinishAddIndexOffset : Nat -> Prop
  | offset115 : ProgramLookupNativeFinishAddIndexOffset 115
  | offset140 : ProgramLookupNativeFinishAddIndexOffset 140

inductive ProgramLookupNativeFinishScaleEightOffset : Nat -> Prop
  | offset117 : ProgramLookupNativeFinishScaleEightOffset 117
  | offset142 : ProgramLookupNativeFinishScaleEightOffset 142

inductive ProgramLookupNativeFinishAddBaseOffset : Nat -> Prop
  | offset120 : ProgramLookupNativeFinishAddBaseOffset 120
  | offset145 : ProgramLookupNativeFinishAddBaseOffset 145

theorem programLookupNativeFinishLowLoad_edx
    (edge : ProgramLookupNativeFinishLowLoadOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.edx =
      Memory.read32 state.memory
        (state.registers.ebp + BitVec.ofNat 32 (2 ^ 32 - 4)) := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishMoveIndex_eax
    (edge : ProgramLookupNativeFinishMoveIndexOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.eax = state.registers.edx := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishMoveIndex_edx
    (edge : ProgramLookupNativeFinishMoveIndexOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.edx = state.registers.edx := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishScaleFour_eax
    (edge : ProgramLookupNativeFinishScaleFourOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.eax = state.registers.eax <<< 2 := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishScaleFour_edx
    (edge : ProgramLookupNativeFinishScaleFourOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.edx = state.registers.edx := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishAddIndex_eax
    (edge : ProgramLookupNativeFinishAddIndexOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.eax =
      state.registers.eax + state.registers.edx := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishScaleEight_eax
    (edge : ProgramLookupNativeFinishScaleEightOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.eax = state.registers.eax <<< 3 := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, Expr.addNormalized, readOperand32,
        writeOperand32, Addressing.expression, symbolicRead32,
        exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
        programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
        StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
        StageA.Formal.applyWrites]

theorem programLookupNativeFinishAddBase_eax
    (edge : ProgramLookupNativeFinishAddBaseOffset offset)
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters offset
      undefinedSlot state).registers.eax =
      state.registers.eax +
        BitVec.ofNat 32 (pe.imageBase + parameters.tableRva) := by
  cases edge <;>
    simp (config := { maxSteps := 1000000 })
      [programLookupNativeExpectedStepState,
        stepProgramLookupNativeExpectedInstruction,
        programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
        stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
        executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
        SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
        Registers.set, Registers.get, readOperand32, writeOperand32,
        Addressing.expression, symbolicRead32, exactWrite32WithDisjointTail?,
        programLookupNativeEbpMemory, programLookupNativeMemoryOperand,
        StageA.Formal.Expr.eval, StageA.Formal.BoolExpr.eval,
        StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
        evalInputRegAddNormalizedConstant]

theorem programLookupNativeFinishRecordLoad_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 125
      undefinedSlot state).registers.eax =
      Memory.read32 state.memory state.registers.eax := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.addNormalized, readOperand32,
      writeOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeFinishJump_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeExpectedStepState pe imports environment parameters 150
      undefinedSlot state).registers.eax = state.registers.eax := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      nextNativeExecution, executeInstructionWithContext, executeInstruction, relativeTarget8,
      concreteBehaviorNextMachineState, SymbolicBehavior.eval, initialSymbolic,
      initialSymbolicX87, Registers.set, Registers.get, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites]

theorem programLookupNativeFinishRecordResult_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva index undefinedSlot : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva index index before state)
    (recordAt : listAt? records index = some record) :
    (programLookupNativeFinishRecordResult pe imports environment parameters
      undefinedSlot state).registers.eax = BitVec.ofNat 32 record.sourceRva := by
  have tableRead := cutpoint.tableLoaded index record recordAt
  let state110 := programLookupNativeExpectedStepState pe imports environment
    parameters 107 undefinedSlot state
  let state112 := programLookupNativeExpectedStepState pe imports environment
    parameters 110 (undefinedSlot + 1) state110
  let state115 := programLookupNativeExpectedStepState pe imports environment
    parameters 112 (undefinedSlot + 2) state112
  let state117 := programLookupNativeExpectedStepState pe imports environment
    parameters 115 (undefinedSlot + 3) state115
  let state120 := programLookupNativeExpectedStepState pe imports environment
    parameters 117 (undefinedSlot + 4) state117
  let state125 := programLookupNativeExpectedStepState pe imports environment
    parameters 120 (undefinedSlot + 5) state120
  have mem110 : state110.memory = state.memory :=
    programLookupNativeFinishStep_memory .offset107 pe imports environment
      parameters undefinedSlot state
  have mem112 : state112.memory = state110.memory :=
    programLookupNativeFinishStep_memory .offset110 pe imports environment
      parameters (undefinedSlot + 1) state110
  have mem115 : state115.memory = state112.memory :=
    programLookupNativeFinishStep_memory .offset112 pe imports environment
      parameters (undefinedSlot + 2) state112
  have mem117 : state117.memory = state115.memory :=
    programLookupNativeFinishStep_memory .offset115 pe imports environment
      parameters (undefinedSlot + 3) state115
  have mem120 : state120.memory = state117.memory :=
    programLookupNativeFinishStep_memory .offset117 pe imports environment
      parameters (undefinedSlot + 4) state117
  have mem125 : state125.memory = state120.memory :=
    programLookupNativeFinishStep_memory .offset120 pe imports environment
      parameters (undefinedSlot + 5) state120
  unfold programLookupNativeFinishRecordResult
  rw [programLookupNativeFinishRecordLoad_eax, mem125, mem120, mem117, mem115,
    mem112, mem110]
  rw [programLookupNativeFinishAddBase_eax .offset120,
    programLookupNativeFinishScaleEight_eax .offset117,
    programLookupNativeFinishAddIndex_eax .offset115,
    programLookupNativeFinishScaleFour_eax .offset112,
    programLookupNativeFinishMoveIndex_eax .offset110,
    programLookupNativeFinishLowLoad_edx .offset107]
  rw [programLookupNativeFinishScaleFour_edx .offset112,
    programLookupNativeFinishMoveIndex_edx .offset110,
    programLookupNativeFinishLowLoad_edx .offset107]
  rw [cutpoint.framePointerExact, programLookupSavedFrameAddress,
    programLookupLowEbpAddressAdd, cutpoint.lowSlotExact]
  rw [programLookupTableAddressWord, tableRead]

theorem programLookupNativeFinishCompareResult_zero_iff
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (undefinedSlot sourceRva : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (framePointerExact : state.registers.ebp =
      programLookupSavedEbpSlot before.registers.esp)
    (sourceExact : Memory.read32 state.memory
      (before.registers.esp + BitVec.ofNat 32 4) = BitVec.ofNat 32 sourceRva)
    (eaxExact : state.registers.eax = BitVec.ofNat 32 record.sourceRva)
    (recordFits : record.sourceRva < 2 ^ 32)
    (sourceFits : sourceRva < 2 ^ 32) :
    programLookupFlagIs
        (programLookupNativeFinishCompareResult pe imports environment parameters
          undefinedSlot state) 6 true ↔ sourceRva = record.sourceRva := by
  simp (config := { maxSteps := 1000000 })
    [programLookupNativeFinishCompareResult, programLookupFlagIs,
      programLookupNativeExpectedStepState,
      stepProgramLookupNativeExpectedInstruction,
      programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
      stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
      executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Registers.set, Registers.get, Expr.subNormalized,
      readOperand32, Addressing.expression, symbolicRead32,
      exactWrite32WithDisjointTail?, programLookupNativeEbpMemory,
      programLookupNativeMemoryOperand, StageA.Formal.Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.applyWrites, evalFlagBit,
      subtractionFlags_applyToExpression_extract_zero,
      subtractionFlags, framePointerExact, programLookupSourceArgumentEbpAddress,
      sourceExact, eaxExact, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt recordFits, Nat.mod_eq_of_lt sourceFits]
  constructor
  · intro differenceZero
    have wordsEqual :
        BitVec.ofNat 32 sourceRva = BitVec.ofNat 32 record.sourceRva := by
      simpa using BitVec.sub_eq_iff_eq_add.mp differenceZero
    have naturalsEqual := congrArg BitVec.toNat wordsEqual
    simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt sourceFits,
      Nat.mod_eq_of_lt recordFits] using naturalsEqual
  · intro equal
    subst sourceRva
    simp

theorem programLookupNativeFinishPointerResult_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters)
    (index undefinedSlot : Nat) (before state : MachineState)
    (framePointerExact : state.registers.ebp =
      programLookupSavedEbpSlot before.registers.esp)
    (indexExact : Memory.read32 state.memory
      (programLookupLowSlot before.registers.esp) = BitVec.ofNat 32 index) :
    (programLookupNativeFinishPointerResult pe imports environment parameters
      undefinedSlot state).registers.eax =
        word32 (pe.imageBase + parameters.tableRva +
          index * transferRecordSize) := by
  have lowAddress :
      programLookupSavedEbpSlot before.registers.esp +
          BitVec.ofNat 32 (2 ^ 32 - 4) =
        programLookupLowSlot before.registers.esp := by
    unfold programLookupSavedEbpSlot programLookupLowSlot programLookupFrameByte
    bv_decide
  let state135 := programLookupNativeExpectedStepState pe imports environment
    parameters 132 undefinedSlot state
  let state137 := programLookupNativeExpectedStepState pe imports environment
    parameters 135 (undefinedSlot + 1) state135
  let state140 := programLookupNativeExpectedStepState pe imports environment
    parameters 137 (undefinedSlot + 2) state137
  let state142 := programLookupNativeExpectedStepState pe imports environment
    parameters 140 (undefinedSlot + 3) state140
  let state145 := programLookupNativeExpectedStepState pe imports environment
    parameters 142 (undefinedSlot + 4) state142
  let state150 := programLookupNativeExpectedStepState pe imports environment
    parameters 145 (undefinedSlot + 5) state145
  unfold programLookupNativeFinishPointerResult
  rw [programLookupNativeFinishJump_eax,
    programLookupNativeFinishAddBase_eax .offset145,
    programLookupNativeFinishScaleEight_eax .offset142,
    programLookupNativeFinishAddIndex_eax .offset140,
    programLookupNativeFinishScaleFour_eax .offset137,
    programLookupNativeFinishMoveIndex_eax .offset135,
    programLookupNativeFinishLowLoad_edx .offset132]
  rw [programLookupNativeFinishScaleFour_edx .offset137,
    programLookupNativeFinishMoveIndex_edx .offset135,
    programLookupNativeFinishLowLoad_edx .offset132]
  rw [framePointerExact, lowAddress, indexExact]
  rw [programLookupTableAddressWord]
  rfl

theorem programLookupNativeFinishZeroResult_eax
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) :
    (programLookupNativeFinishZeroResult pe imports environment parameters
      undefinedSlot state).registers.eax = word32 0 := by
  simp [programLookupNativeFinishZeroResult, word32,
    programLookupNativeExpectedStepState,
    stepProgramLookupNativeExpectedInstruction,
    programLookupNativeExpectedDecoded?, programLookupNativeExpectedInstruction?,
    stepDecodedPE32Instruction, continueProgramLookupNativeExecution,
    executeInstructionWithContext, executeInstruction, concreteBehaviorNextMachineState,
    SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
    Registers.set, Registers.get, StageA.Formal.Expr.eval,
    StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
    StageA.Formal.applyWrites]

def programLookupNativeIterationGuardResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeGuardResult pe imports environment parameters undefinedSlot
    state

def programLookupNativeIterationMidpointResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeMidpointResult pe imports environment parameters 0
    (programLookupNativeIterationGuardResult pe imports environment parameters
      undefinedSlot state)

def programLookupNativeIterationRecordResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeRecordResult pe imports environment parameters 7
    (programLookupNativeIterationMidpointResult pe imports environment parameters
      undefinedSlot state)

def programLookupNativeIterationCompareResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeCompareResult pe imports environment parameters 15
    (programLookupNativeIterationRecordResult pe imports environment parameters
      undefinedSlot state)

def programLookupNativeIterationBranchResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeExpectedStepState pe imports environment parameters 70 17
    (programLookupNativeIterationCompareResult pe imports environment parameters
      undefinedSlot state)

def programLookupNativeLowerIterationResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  let update := programLookupNativeLowerUpdateResult pe imports environment
    parameters 0 (programLookupNativeIterationBranchResult pe imports environment
      parameters undefinedSlot state)
  programLookupNativeExpectedStepState pe imports environment parameters 81 3
    update

def programLookupNativeUpperIterationResult
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (parameters : ProgramLookupTemplateParameters) (undefinedSlot : Nat)
    (state : MachineState) : MachineState :=
  programLookupNativeUpperUpdateResult pe imports environment parameters
    (programLookupNativeIterationBranchResult pe imports environment parameters
      undefinedSlot state)

theorem ProgramLookupNativeInstructionInventory.runLowerIterationExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (notConverged : low < high)
    (carry : programLookupFlagIs
      (programLookupNativeCompareResult pe imports environment parameters 15
        (programLookupNativeRecordResult pe imports environment parameters 7
          (programLookupNativeMidpointResult pe imports environment parameters 0
            (programLookupNativeGuardResult pe imports environment parameters
              undefinedSlot state)))) 0 true) :
    runProgramLookupNativeFuel pe imports environment 25
        (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 89) 0
        (programLookupNativeLowerIterationResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [show 25 = 3 + 22 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runLoopGuardTakenExact imports environment records transferCount
    sourceRva low high undefinedSlot before state cutpoint notConverged]
  rw [show 22 = 7 + 15 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runMidpointExact imports environment 0]
  rw [show 15 = 8 + 7 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runRecordExact imports environment 7]
  rw [show 7 = 2 + 5 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runCompareExact imports environment 15]
  rw [runProgramLookupNativeFuel]
  rw [inventory.stepNativeAt imports environment 70 (by decide)]
  rw [programLookupNativeStep70Lower pe imports environment parameters 17 _ carry]
  rw [inventory.runLowerUpdateExact imports environment 0]
  rfl

theorem ProgramLookupNativeInstructionInventory.runUpperIterationExact
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (notConverged : low < high)
    (noCarry : programLookupFlagIs
      (programLookupNativeCompareResult pe imports environment parameters 15
        (programLookupNativeRecordResult pe imports environment parameters 7
          (programLookupNativeMidpointResult pe imports environment parameters 0
            (programLookupNativeGuardResult pe imports environment parameters
              undefinedSlot state)))) 0 false) :
    runProgramLookupNativeFuel pe imports environment 23
        (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
      .running (parameters.entryRva + 89) 2
        (programLookupNativeUpperIterationResult pe imports environment parameters
          undefinedSlot state) [] 0 [] := by
  rw [show 23 = 3 + 20 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runLoopGuardTakenExact imports environment records transferCount
    sourceRva low high undefinedSlot before state cutpoint notConverged]
  rw [show 20 = 7 + 13 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runMidpointExact imports environment 0]
  rw [show 13 = 8 + 5 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runRecordExact imports environment 7]
  rw [show 5 = 2 + 3 by omega, runProgramLookupNativeFuel_add]
  rw [inventory.runCompareExact imports environment 15]
  rw [runProgramLookupNativeFuel]
  rw [inventory.stepNativeAt imports environment 70 (by decide)]
  rw [programLookupNativeStep70Upper pe imports environment parameters 17 _ noCarry]
  rw [inventory.runUpperUpdateExact imports environment]
  rfl

theorem ProgramLookupNativeInstructionInventory.lowerIterationLaw
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high midpoint : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (undefinedSlot : Nat) (notConverged : low < high)
    (midpointExact : midpoint = low + (high - low) / 2)
    (recordAt : listAt? records midpoint = some record)
    (recordLess : record.sourceRva < sourceRva) :
    exists nextState,
      runProgramLookupNativeFuel pe imports environment 25
          (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
        .running (parameters.entryRva + 89) 0 nextState [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
        (midpoint + 1) high before nextState := by
  let guard := programLookupNativeIterationGuardResult pe imports environment
    parameters undefinedSlot state
  let midpointState := programLookupNativeIterationMidpointResult pe imports
    environment parameters undefinedSlot state
  let recordState := programLookupNativeIterationRecordResult pe imports environment
    parameters undefinedSlot state
  let compareState := programLookupNativeIterationCompareResult pe imports environment
    parameters undefinedSlot state
  let branchState := programLookupNativeIterationBranchResult pe imports environment
    parameters undefinedSlot state
  let nextState := programLookupNativeLowerIterationResult pe imports environment
    parameters undefinedSlot state
  have guardMachine : ProgramLookupNativeLoopMachinePreserved state guard := {
    esp := programLookupNativeGuardResult_esp pe imports environment parameters
      undefinedSlot state
    ebp := programLookupNativeGuardResult_ebp pe imports environment parameters
      undefinedSlot state
    preserved := programLookupNativeGuardResult_preserved pe imports environment
      parameters undefinedSlot state
  }
  have guardCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low high before guard := by
    simpa [guard, programLookupNativeIterationGuardResult] using
      cutpoint.afterGuard imports environment undefinedSlot
  have midpointMachine : ProgramLookupNativeLoopMachinePreserved guard
      midpointState := by
    simpa [guard, midpointState, programLookupNativeIterationGuardResult,
      programLookupNativeIterationMidpointResult] using
      programLookupNativeMidpointResult_machinePreserved pe imports environment
        parameters 0 guard
  have midpointMemory : midpointState.memory = guard.memory.write32
      (programLookupMidpointSlot before.registers.esp)
      (BitVec.ofNat 32 midpoint) := by
    simpa [guard, midpointState, programLookupNativeIterationGuardResult,
      programLookupNativeIterationMidpointResult] using
      programLookupNativeMidpointResult_memory pe imports environment parameters
        records transferCount sourceRva low high midpoint 0 before guard guardCutpoint
        midpointExact
  have midpointCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low high before midpointState := by
    apply guardCutpoint.afterScratchWrite 4 (by omega) (BitVec.ofNat 32 midpoint)
      midpointMachine
    · simpa [programLookupMidpointSlot] using midpointMemory
    · simpa [programLookupSavedEbpSlot] using
        programLookupFrameWordsAvoid before.registers.esp 16 4
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupLowSlot] using
        programLookupFrameWordsAvoid before.registers.esp 12 4
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupHighSlot] using
        programLookupFrameWordsAvoid before.registers.esp 8 4
          (by omega) (by omega) (Or.inr (by omega))
  have midpointRead : Memory.read32 midpointState.memory
      (programLookupMidpointSlot before.registers.esp) =
        BitVec.ofNat 32 midpoint := by
    rw [midpointMemory, Memory.read32_write32_same_of_fits]
    simpa [programLookupMidpointSlot] using
      programLookupFrameWordFits before.registers.esp 4 cutpoint.stackHasFrame
        (by omega)
  have tableRead := midpointCutpoint.tableLoaded midpoint record recordAt
  have recordPreEax :
      (programLookupNativeRecordPreWriteResult pe imports environment parameters 7
        midpointState).registers.eax = BitVec.ofNat 32 record.sourceRva := by
    exact programLookupNativeRecordPreWriteResult_eax pe imports environment
      parameters 7 midpoint record before midpointState
      midpointCutpoint.framePointerExact midpointRead tableRead
  have recordMachine : ProgramLookupNativeLoopMachinePreserved midpointState
      recordState := by
    simpa [midpointState, recordState, programLookupNativeIterationMidpointResult,
      programLookupNativeIterationRecordResult] using
      programLookupNativeRecordResult_machinePreserved pe imports environment
        parameters 7 midpointState
  have recordMemory : recordState.memory = midpointState.memory.write32
      (programLookupRecordSlot before.registers.esp)
      (BitVec.ofNat 32 record.sourceRva) := by
    simp only [recordState, midpointState, programLookupNativeIterationRecordResult]
    rw [programLookupNativeRecordResult_memory]
    rw [midpointCutpoint.framePointerExact, programLookupSavedFrameAddress,
      programLookupRecordEbpAddress, recordPreEax]
  have recordCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low high before recordState := by
    apply midpointCutpoint.afterScratchWrite 0 (by omega)
      (BitVec.ofNat 32 record.sourceRva) recordMachine
    · simpa [programLookupRecordSlot] using recordMemory
    · simpa [programLookupSavedEbpSlot] using
        programLookupFrameWordsAvoid before.registers.esp 16 0
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupLowSlot] using
        programLookupFrameWordsAvoid before.registers.esp 12 0
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupHighSlot] using
        programLookupFrameWordsAvoid before.registers.esp 8 0
          (by omega) (by omega) (Or.inr (by omega))
  have compareMachine : ProgramLookupNativeLoopMachinePreserved recordState
      compareState := by
    simpa [recordState, compareState, programLookupNativeIterationRecordResult,
      programLookupNativeIterationCompareResult] using
      programLookupNativeCompareResult_machinePreserved pe imports environment
        parameters 15 recordState
  have compareMemory : compareState.memory = recordState.memory := by
    simpa [recordState, compareState, programLookupNativeIterationRecordResult,
      programLookupNativeIterationCompareResult] using
      programLookupNativeCompareResult_memory pe imports environment parameters 15
        recordState
  have compareCutpoint := recordCutpoint.afterMemoryPreserved compareMachine
    compareMemory
  have recordFits : record.sourceRva < 2 ^ 32 :=
    programLookupRecordSourcesFit_listAt records cutpoint.recordSourcesFit midpoint
      record recordAt
  have recordRead : Memory.read32 recordState.memory
      (programLookupRecordSlot before.registers.esp) =
        BitVec.ofNat 32 record.sourceRva := by
    rw [recordMemory, Memory.read32_write32_same_of_fits]
    simpa [programLookupRecordSlot] using
      programLookupFrameWordFits before.registers.esp 0 cutpoint.stackHasFrame
        (by omega)
  have carry : programLookupFlagIs compareState 0 true := by
    apply (programLookupNativeCompareResult_carry_iff pe imports environment
      parameters 15 sourceRva record before recordState
      recordCutpoint.framePointerExact recordRead
      recordCutpoint.sourceArgumentPreserved recordFits cutpoint.sourceFits).2
    exact recordLess
  have branchMachine : ProgramLookupNativeLoopMachinePreserved compareState
      branchState := by
    simpa [compareState, branchState, programLookupNativeIterationCompareResult,
      programLookupNativeIterationBranchResult] using
      programLookupNativeStep70_machinePreserved pe imports environment parameters 17
        compareState
  have branchMemory : branchState.memory = compareState.memory := by
    simpa [compareState, branchState, programLookupNativeIterationCompareResult,
      programLookupNativeIterationBranchResult] using
      programLookupNativeStep70_memory pe imports environment parameters 17
        compareState
  have branchCutpoint := compareCutpoint.afterMemoryPreserved branchMachine
    branchMemory
  have midpointReadAtRecord : Memory.read32 recordState.memory
      (programLookupMidpointSlot before.registers.esp) =
        BitVec.ofNat 32 midpoint := by
    rw [recordMemory, Memory.read32_write32_of_avoids]
    exact midpointRead
    simpa [programLookupMidpointSlot, programLookupRecordSlot] using
      programLookupFrameWordsAvoid before.registers.esp 4 0
        (by omega) (by omega) (Or.inr (by omega))
  have midpointReadAtBranch : Memory.read32 branchState.memory
      (programLookupMidpointSlot before.registers.esp) =
        BitVec.ofNat 32 midpoint := by
    rw [branchMemory, compareMemory]
    exact midpointReadAtRecord
  have updateMachine : ProgramLookupNativeLoopMachinePreserved branchState
      nextState := by
    let update := programLookupNativeLowerUpdateResult pe imports environment
      parameters 0 branchState
    have updatePreserved := programLookupNativeLowerUpdateResult_machinePreserved pe
      imports environment parameters 0 branchState
    have jumpPreserved := programLookupNativeStep81_machinePreserved pe imports
      environment parameters 3 update
    simpa [nextState, programLookupNativeLowerIterationResult, update] using
      updatePreserved.trans jumpPreserved
  have nextMemory : nextState.memory = branchState.memory.write32
      (programLookupLowSlot before.registers.esp)
      (BitVec.ofNat 32 (midpoint + 1)) := by
    simp only [nextState, branchState, programLookupNativeLowerIterationResult]
    rw [programLookupNativeStep81_memory,
      programLookupNativeLowerUpdateResult_memory]
    rw [branchCutpoint.framePointerExact, programLookupSavedFrameAddress,
      programLookupLowEbpAddressAdd, programLookupMidpointEbpAddress,
      midpointReadAtBranch]
    simp [← BitVec.ofNat_add]
  have nextCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva (midpoint + 1) high before nextState := by
    apply branchCutpoint.afterLowWrite (midpoint + 1) (by
      simp only [midpointExact]
      omega) updateMachine nextMemory
  refine ⟨nextState, ?_, nextCutpoint⟩
  exact inventory.runLowerIterationExact imports environment records transferCount
    sourceRva low high undefinedSlot before state cutpoint notConverged carry

theorem ProgramLookupNativeInstructionInventory.upperIterationLaw
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount sourceRva low high midpoint : Nat)
    (record : StageA.Relational.Interpreter.ProgramRecord)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva low high before state)
    (undefinedSlot : Nat) (notConverged : low < high)
    (midpointExact : midpoint = low + (high - low) / 2)
    (recordAt : listAt? records midpoint = some record)
    (recordNotLess : ¬ record.sourceRva < sourceRva) :
    exists nextState,
      runProgramLookupNativeFuel pe imports environment 23
          (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
        .running (parameters.entryRva + 89) 2 nextState [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
        low midpoint before nextState := by
  let guard := programLookupNativeIterationGuardResult pe imports environment
    parameters undefinedSlot state
  let midpointState := programLookupNativeIterationMidpointResult pe imports
    environment parameters undefinedSlot state
  let recordState := programLookupNativeIterationRecordResult pe imports environment
    parameters undefinedSlot state
  let compareState := programLookupNativeIterationCompareResult pe imports environment
    parameters undefinedSlot state
  let branchState := programLookupNativeIterationBranchResult pe imports environment
    parameters undefinedSlot state
  let nextState := programLookupNativeUpperIterationResult pe imports environment
    parameters undefinedSlot state
  have guardCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low high before guard := by
    simpa [guard, programLookupNativeIterationGuardResult] using
      cutpoint.afterGuard imports environment undefinedSlot
  have midpointMachine : ProgramLookupNativeLoopMachinePreserved guard
      midpointState := by
    simpa [guard, midpointState, programLookupNativeIterationGuardResult,
      programLookupNativeIterationMidpointResult] using
      programLookupNativeMidpointResult_machinePreserved pe imports environment
        parameters 0 guard
  have midpointMemory : midpointState.memory = guard.memory.write32
      (programLookupMidpointSlot before.registers.esp)
      (BitVec.ofNat 32 midpoint) := by
    simpa [guard, midpointState, programLookupNativeIterationGuardResult,
      programLookupNativeIterationMidpointResult] using
      programLookupNativeMidpointResult_memory pe imports environment parameters
        records transferCount sourceRva low high midpoint 0 before guard guardCutpoint
        midpointExact
  have midpointCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low high before midpointState := by
    apply guardCutpoint.afterScratchWrite 4 (by omega) (BitVec.ofNat 32 midpoint)
      midpointMachine
    · simpa [programLookupMidpointSlot] using midpointMemory
    · simpa [programLookupSavedEbpSlot] using
        programLookupFrameWordsAvoid before.registers.esp 16 4
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupLowSlot] using
        programLookupFrameWordsAvoid before.registers.esp 12 4
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupHighSlot] using
        programLookupFrameWordsAvoid before.registers.esp 8 4
          (by omega) (by omega) (Or.inr (by omega))
  have midpointRead : Memory.read32 midpointState.memory
      (programLookupMidpointSlot before.registers.esp) =
        BitVec.ofNat 32 midpoint := by
    rw [midpointMemory, Memory.read32_write32_same_of_fits]
    simpa [programLookupMidpointSlot] using
      programLookupFrameWordFits before.registers.esp 4 cutpoint.stackHasFrame
        (by omega)
  have tableRead := midpointCutpoint.tableLoaded midpoint record recordAt
  have recordPreEax :
      (programLookupNativeRecordPreWriteResult pe imports environment parameters 7
        midpointState).registers.eax = BitVec.ofNat 32 record.sourceRva := by
    exact programLookupNativeRecordPreWriteResult_eax pe imports environment
      parameters 7 midpoint record before midpointState
      midpointCutpoint.framePointerExact midpointRead tableRead
  have recordMachine : ProgramLookupNativeLoopMachinePreserved midpointState
      recordState := by
    simpa [midpointState, recordState, programLookupNativeIterationMidpointResult,
      programLookupNativeIterationRecordResult] using
      programLookupNativeRecordResult_machinePreserved pe imports environment
        parameters 7 midpointState
  have recordMemory : recordState.memory = midpointState.memory.write32
      (programLookupRecordSlot before.registers.esp)
      (BitVec.ofNat 32 record.sourceRva) := by
    simp only [recordState, midpointState, programLookupNativeIterationRecordResult]
    rw [programLookupNativeRecordResult_memory]
    rw [midpointCutpoint.framePointerExact, programLookupSavedFrameAddress,
      programLookupRecordEbpAddress, recordPreEax]
  have recordCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low high before recordState := by
    apply midpointCutpoint.afterScratchWrite 0 (by omega)
      (BitVec.ofNat 32 record.sourceRva) recordMachine
    · simpa [programLookupRecordSlot] using recordMemory
    · simpa [programLookupSavedEbpSlot] using
        programLookupFrameWordsAvoid before.registers.esp 16 0
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupLowSlot] using
        programLookupFrameWordsAvoid before.registers.esp 12 0
          (by omega) (by omega) (Or.inr (by omega))
    · simpa [programLookupHighSlot] using
        programLookupFrameWordsAvoid before.registers.esp 8 0
          (by omega) (by omega) (Or.inr (by omega))
  have compareMachine : ProgramLookupNativeLoopMachinePreserved recordState
      compareState := by
    simpa [recordState, compareState, programLookupNativeIterationRecordResult,
      programLookupNativeIterationCompareResult] using
      programLookupNativeCompareResult_machinePreserved pe imports environment
        parameters 15 recordState
  have compareMemory : compareState.memory = recordState.memory := by
    simpa [recordState, compareState, programLookupNativeIterationRecordResult,
      programLookupNativeIterationCompareResult] using
      programLookupNativeCompareResult_memory pe imports environment parameters 15
        recordState
  have compareCutpoint := recordCutpoint.afterMemoryPreserved compareMachine
    compareMemory
  have recordFits : record.sourceRva < 2 ^ 32 :=
    programLookupRecordSourcesFit_listAt records cutpoint.recordSourcesFit midpoint
      record recordAt
  have recordRead : Memory.read32 recordState.memory
      (programLookupRecordSlot before.registers.esp) =
        BitVec.ofNat 32 record.sourceRva := by
    rw [recordMemory, Memory.read32_write32_same_of_fits]
    simpa [programLookupRecordSlot] using
      programLookupFrameWordFits before.registers.esp 0 cutpoint.stackHasFrame
        (by omega)
  have noCarry : programLookupFlagIs compareState 0 false := by
    apply (programLookupNativeCompareResult_noCarry_iff pe imports environment
      parameters 15 sourceRva record before recordState
      recordCutpoint.framePointerExact recordRead
      recordCutpoint.sourceArgumentPreserved recordFits cutpoint.sourceFits).2
    exact recordNotLess
  have branchMachine : ProgramLookupNativeLoopMachinePreserved compareState
      branchState := by
    simpa [compareState, branchState, programLookupNativeIterationCompareResult,
      programLookupNativeIterationBranchResult] using
      programLookupNativeStep70_machinePreserved pe imports environment parameters 17
        compareState
  have branchMemory : branchState.memory = compareState.memory := by
    simpa [compareState, branchState, programLookupNativeIterationCompareResult,
      programLookupNativeIterationBranchResult] using
      programLookupNativeStep70_memory pe imports environment parameters 17
        compareState
  have branchCutpoint := compareCutpoint.afterMemoryPreserved branchMachine
    branchMemory
  have midpointReadAtRecord : Memory.read32 recordState.memory
      (programLookupMidpointSlot before.registers.esp) =
        BitVec.ofNat 32 midpoint := by
    rw [recordMemory, Memory.read32_write32_of_avoids]
    exact midpointRead
    simpa [programLookupMidpointSlot, programLookupRecordSlot] using
      programLookupFrameWordsAvoid before.registers.esp 4 0
        (by omega) (by omega) (Or.inr (by omega))
  have midpointReadAtBranch : Memory.read32 branchState.memory
      (programLookupMidpointSlot before.registers.esp) =
        BitVec.ofNat 32 midpoint := by
    rw [branchMemory, compareMemory]
    exact midpointReadAtRecord
  have updateMachine : ProgramLookupNativeLoopMachinePreserved branchState
      nextState := by
    simpa [nextState, programLookupNativeUpperIterationResult] using
      programLookupNativeUpperUpdateResult_machinePreserved pe imports environment
        parameters branchState
  have nextMemory : nextState.memory = branchState.memory.write32
      (programLookupHighSlot before.registers.esp)
      (BitVec.ofNat 32 midpoint) := by
    simp only [nextState, branchState, programLookupNativeUpperIterationResult]
    rw [programLookupNativeUpperUpdateResult_memory]
    rw [branchCutpoint.framePointerExact, programLookupSavedFrameAddress,
      programLookupHighEbpAddress,
      programLookupMidpointEbpAddress, midpointReadAtBranch]
  have nextCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva low midpoint before nextState := by
    apply branchCutpoint.afterHighWrite midpoint (by
      simp only [midpointExact]
      omega) (by
      have midpointLtHigh : midpoint < high := by
        simp only [midpointExact]
        omega
      exact Nat.le_trans (Nat.le_of_lt midpointLtHigh) cutpoint.bounds.2)
      updateMachine nextMemory
  refine ⟨nextState, ?_, nextCutpoint⟩
  exact inventory.runUpperIterationExact imports environment records transferCount
    sourceRva low high undefinedSlot before state cutpoint notConverged noCarry

/-- The exact finite finish paths implement the lower-bound lookup result.  The
only data-dependent choices are the two decoded conditional branches; every
intermediate state is produced by the native executor and lifted through the
authoritative loop cutpoint. -/
theorem ProgramLookupNativeInstructionInventory.finishLaw
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (recordsSorted : sourceRvasStrictlySorted records)
    (transferCount sourceRva index undefinedSlot : Nat)
    (before state : MachineState)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe parameters records transferCount
      sourceRva index index before state)
    (trace : ReflectedProgramLookupTrace records sourceRva 0 transferCount index) :
    exists fuel epilogueSlot epilogueState,
      0 < fuel /\ fuel <= 22 /\
      runProgramLookupNativeFuel pe imports environment fuel
        (.running (parameters.entryRva + 89) undefinedSlot state [] 0 []) =
          .running (parameters.entryRva + 157) epilogueSlot epilogueState [] 0 [] /\
      ProgramLookupNativeEpilogueCutpoint pe parameters records sourceRva before
        epilogueState := by
  have normalizedTrace : ReflectedProgramLookupTrace records sourceRva 0
      records.length index := by
    simpa [cutpoint.transferCountExact] using trace
  have bound : ProgramLookupLowerBound records sourceRva index :=
    reflectedProgramLookupTrace_lowerBound normalizedTrace recordsSorted
  let guard := programLookupNativeGuardResult pe imports environment parameters
    undefinedSlot state
  let count := programLookupNativeFinishCountResult pe imports environment
    parameters 0 guard
  let countBranch := programLookupNativeFinishCountBranchResult pe imports
    environment parameters 2 count
  have guardExact := inventory.runLoopGuardExitExact imports environment records
    transferCount sourceRva index undefinedSlot before state cutpoint
  have guardCutpoint : ProgramLookupNativeLoopCutpoint pe parameters records
      transferCount sourceRva index index before guard := by
    simpa [guard] using cutpoint.afterGuard imports environment undefinedSlot
  have countMachine : ProgramLookupNativeLoopMachinePreserved guard count := by
    simpa [count] using programLookupNativeFinishCountResult_machinePreserved pe
      imports environment parameters 0 guard
  have countMemory : count.memory = guard.memory := by
    simpa [count] using programLookupNativeFinishCountResult_memory pe imports
      environment parameters 0 guard
  have countCutpoint := guardCutpoint.afterMemoryPreserved countMachine countMemory
  have countBranchMachine : ProgramLookupNativeLoopMachinePreserved count
      countBranch := by
    simpa [countBranch] using
      programLookupNativeFinishStep_machinePreserved .offset105 pe imports
        environment parameters 2 count
  have countBranchMemory : countBranch.memory = count.memory := by
    simpa [countBranch] using programLookupNativeFinishStep_memory .offset105 pe
      imports environment parameters 2 count
  have countBranchCutpoint := countCutpoint.afterMemoryPreserved
    countBranchMachine countBranchMemory
  cases found : listAt? records index with
  | none =>
      have indexAtEnd : index = transferCount := by
        have lengthBefore := listAt?_none_length_le records index found
        have indexWithin := cutpoint.bounds.2
        rw [← cutpoint.transferCountExact] at lengthBefore
        omega
      have noCarry : programLookupFlagIs count 0 false := by
        apply (programLookupFlagIs_false_iff_not_true count 0).2
        intro carry
        have indexBefore :=
          (programLookupNativeFinishCountResult_carry_iff pe imports environment
            parameters records transferCount sourceRva index 0
            before guard guardCutpoint).1 carry
        omega
      have countBranchExact :
          stepNativeExecution pe imports environment
              (.running (parameters.entryRva + 105) 2
                count [] 0 []) =
            .running (parameters.entryRva + 152) 0 countBranch [] 0 [] := by
        rw [inventory.stepNativeAt imports environment 105 (by decide)]
        simpa [countBranch] using programLookupNativeStep105Taken pe imports
          environment parameters 2 count noCarry
      let zero := programLookupNativeFinishZeroResult pe imports environment
        parameters 0 countBranch
      have zeroMachine : ProgramLookupNativeLoopMachinePreserved countBranch
          zero := by
        simpa [zero] using
          programLookupNativeFinishStep_machinePreserved .offset152 pe imports
            environment parameters 0 countBranch
      have zeroMemory : zero.memory = countBranch.memory := by
        simpa [zero] using programLookupNativeFinishStep_memory .offset152 pe
          imports environment parameters 0 countBranch
      have zeroEax : zero.registers.eax =
          programLookupReturnWord pe parameters.tableRva records sourceRva := by
        unfold programLookupReturnWord
        rw [bound.returnWord recordsSorted pe.imageBase parameters.tableRva]
        simp only [found]
        simpa [zero] using programLookupNativeFinishZeroResult_eax pe imports
          environment parameters 0 countBranch
      have zeroCutpoint := countBranchCutpoint.toEpilogueCutpoint zeroMachine
        zeroMemory zeroEax
      refine ⟨7, 1, zero, by omega, by omega, ?_, zeroCutpoint⟩
      rw [show 7 = 3 + 4 by omega, runProgramLookupNativeFuel_add, guardExact]
      rw [show 4 = 2 + 2 by omega, runProgramLookupNativeFuel_add,
        inventory.runFinishCountExact imports environment]
      rw [show 2 = 1 + 1 by omega, runProgramLookupNativeFuel_add]
      change runProgramLookupNativeFuel pe imports environment 1
        (stepNativeExecution pe imports environment
          (.running (parameters.entryRva + 105) 2 count [] 0 [])) = _
      rw [countBranchExact]
      simpa [zero] using inventory.runFinishZeroExact imports environment 0
        countBranch
  | some record =>
      have indexBefore : index < transferCount := by
        have beforeLength := listAt?_index_lt_length records index record found
        rwa [cutpoint.transferCountExact]
      have carry : programLookupFlagIs count 0 true := by
        apply (programLookupNativeFinishCountResult_carry_iff pe imports environment
          parameters records transferCount sourceRva index 0
          before guard guardCutpoint).2
        exact indexBefore
      have countBranchExact :
          stepNativeExecution pe imports environment
              (.running (parameters.entryRva + 105) 2
                count [] 0 []) =
            .running (parameters.entryRva + 107) 0
              countBranch [] 0 [] := by
        rw [inventory.stepNativeAt imports environment 105 (by decide)]
        simpa [countBranch] using
          programLookupNativeStep105NotTaken pe imports environment parameters
            2 count carry
      let recordState := programLookupNativeFinishRecordResult pe imports
        environment parameters 0 countBranch
      have recordMachine : ProgramLookupNativeLoopMachinePreserved countBranch
          recordState := by
        simpa [recordState] using
          programLookupNativeFinishRecordResult_machinePreserved pe imports
            environment parameters 0 countBranch
      have recordMemory : recordState.memory = countBranch.memory := by
        simpa [recordState] using programLookupNativeFinishRecordResult_memory pe
          imports environment parameters 0 countBranch
      have recordCutpoint := countBranchCutpoint.afterMemoryPreserved recordMachine
        recordMemory
      have recordEax : recordState.registers.eax =
          BitVec.ofNat 32 record.sourceRva := by
        simpa [recordState] using
          programLookupNativeFinishRecordResult_eax pe imports environment
            parameters records transferCount sourceRva index 0
            record before countBranch countBranchCutpoint found
      let compare := programLookupNativeFinishCompareResult pe imports environment
        parameters 7 recordState
      have compareMachine : ProgramLookupNativeLoopMachinePreserved recordState
          compare := by
        simpa [compare] using
          programLookupNativeFinishStep_machinePreserved .offset127 pe imports
            environment parameters 7 recordState
      have compareMemory : compare.memory = recordState.memory := by
        simpa [compare] using programLookupNativeFinishStep_memory .offset127 pe
          imports environment parameters 7 recordState
      have compareCutpoint := recordCutpoint.afterMemoryPreserved compareMachine
        compareMemory
      have recordFits : record.sourceRva < 2 ^ 32 :=
        programLookupRecordSourcesFit_listAt records cutpoint.recordSourcesFit
          index record found
      let matchBranch := programLookupNativeFinishMatchBranchResult pe imports
        environment parameters 8 compare
      have matchBranchMachine : ProgramLookupNativeLoopMachinePreserved compare
          matchBranch := by
        simpa [matchBranch] using
          programLookupNativeFinishStep_machinePreserved .offset130 pe imports
            environment parameters 8 compare
      have matchBranchMemory : matchBranch.memory = compare.memory := by
        simpa [matchBranch] using programLookupNativeFinishStep_memory .offset130 pe
          imports environment parameters 8 compare
      have matchBranchCutpoint := compareCutpoint.afterMemoryPreserved
        matchBranchMachine matchBranchMemory
      by_cases same : record.sourceRva = sourceRva
      · have zeroSet : programLookupFlagIs compare 6 true := by
          apply (programLookupNativeFinishCompareResult_zero_iff pe imports
            environment parameters 7 sourceRva record before
            recordState recordCutpoint.framePointerExact
            recordCutpoint.sourceArgumentPreserved recordEax recordFits
            cutpoint.sourceFits).2
          exact same.symm
        have matchBranchExact :
            stepNativeExecution pe imports environment
                (.running (parameters.entryRva + 130) 8
                  compare [] 0 []) =
              .running (parameters.entryRva + 132) 0
                matchBranch [] 0 [] := by
          rw [inventory.stepNativeAt imports environment 130 (by decide)]
          simpa [matchBranch, Nat.add_assoc] using
            programLookupNativeStep130NotTaken pe imports environment parameters
              8 compare zeroSet
        let pointer := programLookupNativeFinishPointerResult pe imports
          environment parameters 0 matchBranch
        have pointerMachine : ProgramLookupNativeLoopMachinePreserved matchBranch
            pointer := by
          simpa [pointer] using
            programLookupNativeFinishPointerResult_machinePreserved pe imports
              environment parameters 0 matchBranch
        have pointerMemory : pointer.memory = matchBranch.memory := by
          simpa [pointer] using programLookupNativeFinishPointerResult_memory pe
            imports environment parameters 0 matchBranch
        have pointerEax : pointer.registers.eax =
            word32 (pe.imageBase + parameters.tableRva +
              index * transferRecordSize) := by
          simpa [pointer] using programLookupNativeFinishPointerResult_eax pe
            imports environment parameters index 0 before
            matchBranch matchBranchCutpoint.framePointerExact
            matchBranchCutpoint.lowSlotExact
        have returnEax : pointer.registers.eax =
            programLookupReturnWord pe parameters.tableRva records sourceRva := by
          unfold programLookupReturnWord
          rw [bound.returnWord recordsSorted pe.imageBase parameters.tableRva]
          simp only [found, same, if_true]
          exact pointerEax
        have pointerCutpoint := matchBranchCutpoint.toEpilogueCutpoint
          pointerMachine pointerMemory returnEax
        refine ⟨22, 0, pointer, by omega, by omega, ?_, pointerCutpoint⟩
        rw [show 22 = 3 + 19 by omega, runProgramLookupNativeFuel_add, guardExact]
        rw [show 19 = 2 + 17 by omega, runProgramLookupNativeFuel_add,
          inventory.runFinishCountExact imports environment]
        rw [show 17 = 1 + 16 by omega, runProgramLookupNativeFuel_add]
        change runProgramLookupNativeFuel pe imports environment 16
          (stepNativeExecution pe imports environment
            (.running (parameters.entryRva + 105) 2 count [] 0 [])) = _
        rw [countBranchExact]
        rw [show 16 = 7 + 9 by omega, runProgramLookupNativeFuel_add,
          inventory.runFinishRecordExact imports environment]
        rw [show 9 = 1 + 8 by omega, runProgramLookupNativeFuel_add]
        change runProgramLookupNativeFuel pe imports environment 8
          (stepNativeExecution pe imports environment
            (.running (parameters.entryRva + 127) 7 recordState [] 0 [])) = _
        rw [inventory.stepFinishLinearExact imports environment .offset127]
        rw [show 8 = 1 + 7 by omega, runProgramLookupNativeFuel_add]
        change runProgramLookupNativeFuel pe imports environment 7
          (stepNativeExecution pe imports environment
            (.running (parameters.entryRva + 130) 8 compare [] 0 [])) = _
        rw [matchBranchExact]
        simpa [pointer] using inventory.runFinishPointerExact imports environment
          0 matchBranch
      · have zeroClear : programLookupFlagIs compare 6 false := by
          apply (programLookupFlagIs_false_iff_not_true compare 6).2
          intro zeroSet
          have equal := (programLookupNativeFinishCompareResult_zero_iff pe
            imports environment parameters 7 sourceRva record
            before recordState recordCutpoint.framePointerExact
            recordCutpoint.sourceArgumentPreserved recordEax recordFits
            cutpoint.sourceFits).1 zeroSet
          exact same equal.symm
        have matchBranchExact :
            stepNativeExecution pe imports environment
                (.running (parameters.entryRva + 130) 8
                  compare [] 0 []) =
              .running (parameters.entryRva + 152) 0 matchBranch [] 0 [] := by
          rw [inventory.stepNativeAt imports environment 130 (by decide)]
          simpa [matchBranch] using programLookupNativeStep130Taken pe imports
            environment parameters 8 compare zeroClear
        let zero := programLookupNativeFinishZeroResult pe imports environment
          parameters 0 matchBranch
        have zeroMachine : ProgramLookupNativeLoopMachinePreserved matchBranch
            zero := by
          simpa [zero] using
            programLookupNativeFinishStep_machinePreserved .offset152 pe imports
              environment parameters 0 matchBranch
        have zeroMemory : zero.memory = matchBranch.memory := by
          simpa [zero] using programLookupNativeFinishStep_memory .offset152 pe
            imports environment parameters 0 matchBranch
        have zeroEax : zero.registers.eax =
            programLookupReturnWord pe parameters.tableRva records sourceRva := by
          unfold programLookupReturnWord
          rw [bound.returnWord recordsSorted pe.imageBase parameters.tableRva]
          simp only [found, same, if_false]
          simpa [zero] using programLookupNativeFinishZeroResult_eax pe imports
            environment parameters 0 matchBranch
        have zeroCutpoint := matchBranchCutpoint.toEpilogueCutpoint zeroMachine
          zeroMemory zeroEax
        refine ⟨16, 1, zero, by omega, by omega, ?_, zeroCutpoint⟩
        rw [show 16 = 3 + 13 by omega, runProgramLookupNativeFuel_add, guardExact]
        rw [show 13 = 2 + 11 by omega, runProgramLookupNativeFuel_add,
          inventory.runFinishCountExact imports environment]
        rw [show 11 = 1 + 10 by omega, runProgramLookupNativeFuel_add]
        change runProgramLookupNativeFuel pe imports environment 10
          (stepNativeExecution pe imports environment
            (.running (parameters.entryRva + 105) 2 count [] 0 [])) = _
        rw [countBranchExact]
        rw [show 10 = 7 + 3 by omega, runProgramLookupNativeFuel_add,
          inventory.runFinishRecordExact imports environment]
        rw [show 3 = 1 + 2 by omega, runProgramLookupNativeFuel_add]
        change runProgramLookupNativeFuel pe imports environment 2
          (stepNativeExecution pe imports environment
            (.running (parameters.entryRva + 127) 7 recordState [] 0 [])) = _
        rw [inventory.stepFinishLinearExact imports environment .offset127]
        rw [show 2 = 1 + 1 by omega, runProgramLookupNativeFuel_add]
        change runProgramLookupNativeFuel pe imports environment 1
          (stepNativeExecution pe imports environment
            (.running (parameters.entryRva + 130) 8 compare [] 0 [])) = _
        rw [matchBranchExact]
        simpa [zero] using inventory.runFinishZeroExact imports environment 0
          matchBranch

/-- Observable machine facts after the exact three-instruction epilogue.  In
particular this records `leave`, stack return-address consumption, cdecl
callee-save preservation, the return registers, XOR flags, and memory frame. -/
structure ProgramLookupNativeReturnState
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (sourceRva : Nat)
    (before after : MachineState) : Prop where
  eaxExact : after.registers.eax =
    programLookupReturnWord pe parameters.tableRva records sourceRva
  edxZero : after.registers.edx = BitVec.ofNat 32 0
  stackPopped : after.registers.esp =
    before.registers.esp + BitVec.ofNat 32 4
  framePointerRestored : after.registers.ebp = before.registers.ebp
  ebxPreserved : after.registers.ebx = before.registers.ebx
  ecxPreserved : after.registers.ecx = before.registers.ecx
  esiPreserved : after.registers.esi = before.registers.esi
  ediPreserved : after.registers.edi = before.registers.edi
  carryClear : programLookupFlagIs after 0 false
  paritySet : programLookupFlagIs after 2 true
  zeroSet : programLookupFlagIs after 6 true
  signClear : programLookupFlagIs after 7 false
  overflowClear : programLookupFlagIs after 11 false
  directionFlagPreserved :
    after.eflags.extractLsb' 10 1 = before.eflags.extractLsb' 10 1
  undefinedValuesPreserved : after.undefinedValue = before.undefinedValue
  x87Preserved : ProgramLookupArchitecturalX87Preserved before after
  x87PhysicalPreserved : after.x87Physical = before.x87Physical
  x87SemanticsPreserved : after.x87Semantics = before.x87Semantics
  fsBasePreserved : after.fsBase = before.fsBase
  memoryFrame : MemoryAgreesOutside
    (programLookupFrameFootprint before.registers.esp)
    after.memory before.memory

theorem ProgramLookupNativeEpilogueCutpoint.result
    (cutpoint : ProgramLookupNativeEpilogueCutpoint pe parameters records
      sourceRva before state) :
    ProgramLookupNativeReturnState pe parameters records sourceRva before
      (programLookupNativeEpilogueResult undefinedSlot state) := by
  have leaveX87 : ProgramLookupArchitecturalX87Preserved state
      (programLookupNativeLeaveResult state) := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have xorX87 : ProgramLookupArchitecturalX87Preserved
      (programLookupNativeLeaveResult state)
      (programLookupNativeXorEdxResult (undefinedSlot + 1)
        (programLookupNativeLeaveResult state)) := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  have retX87 : ProgramLookupArchitecturalX87Preserved
      (programLookupNativeXorEdxResult (undefinedSlot + 1)
        (programLookupNativeLeaveResult state))
      (programLookupNativeEpilogueResult undefinedSlot state) := by
    apply programLookupNativeOrdinaryX87_preserved_of_x87_eq
    rfl
  refine {
    eaxExact := ?_
    edxZero := ?_
    stackPopped := ?_
    framePointerRestored := ?_
    ebxPreserved := ?_
    ecxPreserved := ?_
    esiPreserved := ?_
    ediPreserved := ?_
    carryClear := ?_
    paritySet := ?_
    zeroSet := ?_
    signClear := ?_
    overflowClear := ?_
    directionFlagPreserved := ?_
    undefinedValuesPreserved := ?_
    x87Preserved := cutpoint.preserved.x87.trans
      (leaveX87.trans (xorX87.trans retX87))
    x87PhysicalPreserved := ?_
    x87SemanticsPreserved := ?_
    fsBasePreserved := ?_
    memoryFrame := ?_
  }
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.eaxExact
  · simp [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult]
  · rw [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult,
      cutpoint.framePointerExact]
    exact programLookupEpilogueStackAddress before.registers.esp
  · simp only [programLookupNativeEpilogueResult,
      programLookupNativeRetResult, programLookupNativeXorEdxResult,
      programLookupNativeLeaveResult]
    rw [cutpoint.framePointerExact]
    rw [programLookupSavedFrameAddress, cutpoint.savedFramePointer]
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.ebx
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.ecx
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.esi
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.edi
  · simp [programLookupFlagIs, programLookupNativeEpilogueResult,
      programLookupNativeRetResult, programLookupNativeXorEdxResult,
      logicalFlags, evalFlagBit, StageA.Formal.BoolExpr.eval,
      StageA.Formal.Expr.eval]
  · simp [programLookupFlagIs, programLookupNativeEpilogueResult,
      programLookupNativeRetResult, programLookupNativeXorEdxResult,
      logicalFlags, evalFlagBit, parityExpression,
      StageA.Formal.BoolExpr.eval, StageA.Formal.Expr.eval]
  · simp [programLookupFlagIs, programLookupNativeEpilogueResult,
      programLookupNativeRetResult, programLookupNativeXorEdxResult,
      logicalFlags, evalFlagBit, StageA.Formal.BoolExpr.eval,
      StageA.Formal.Expr.eval]
  · simp [programLookupFlagIs, programLookupNativeEpilogueResult,
      programLookupNativeRetResult, programLookupNativeXorEdxResult,
      logicalFlags, evalFlagBit, StageA.Formal.BoolExpr.eval,
      StageA.Formal.Expr.eval]
  · simp [programLookupFlagIs, programLookupNativeEpilogueResult,
      programLookupNativeRetResult, programLookupNativeXorEdxResult,
      logicalFlags, evalFlagBit, StageA.Formal.BoolExpr.eval,
      StageA.Formal.Expr.eval]
  · calc
      (programLookupNativeEpilogueResult undefinedSlot state).eflags.extractLsb'
          10 1 =
          (programLookupNativeXorEdxResult (undefinedSlot + 1)
            (programLookupNativeLeaveResult state)).eflags.extractLsb'
              10 1 := by
        simp only [programLookupNativeEpilogueResult,
          programLookupNativeRetResult, programLookupNativeInitialFlags_df]
      _ =
          (programLookupNativeLeaveResult state).eflags.extractLsb' 10 1 := by
        simpa only [programLookupNativeXorEdxResult] using
          StageA.Formal.FlagsExpr.eval_extract_df
            (programLookupNativeLeaveResult state)
            (logicalFlags (undefinedSlot + 1) (.constant 0))
      _ = state.eflags.extractLsb' 10 1 := by
        simp only [programLookupNativeLeaveResult,
          programLookupNativeInitialFlags_df]
      _ = before.eflags.extractLsb' 10 1 :=
        cutpoint.preserved.directionFlag
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.undefinedValue
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.x87Physical
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.x87Semantics
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.preserved.fsBase
  · simpa [programLookupNativeEpilogueResult, programLookupNativeRetResult,
      programLookupNativeXorEdxResult, programLookupNativeLeaveResult] using
      cutpoint.memoryFrame

theorem ProgramLookupNativeInstructionInventory.epilogue
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (sourceRva : Nat) (before state : MachineState) (undefinedSlot : Nat)
    (cutpoint : ProgramLookupNativeEpilogueCutpoint pe parameters records
      sourceRva before state) :
    exists after,
      runProgramLookupNativeFuel pe imports environment 3
        (.running (parameters.entryRva + 157) undefinedSlot state [] 0 []) =
          .returned after [] /\
      ProgramLookupNativeReturnState pe parameters records sourceRva before
        after := by
  exact ⟨programLookupNativeEpilogueResult undefinedSlot state,
    inventory.runEpilogueExact imports environment undefinedSlot state [],
    cutpoint.result⟩

theorem MemoryAgreesOutside.read32_of_bytesOutside
    (frame : MemoryAgreesOutside footprint afterMemory beforeMemory)
    (wordAddress : Word)
    (outside : forall byte, byte < 4 ->
      ¬ footprint (wordAddress + BitVec.ofNat 32 byte)) :
    Memory.read32 afterMemory wordAddress =
      Memory.read32 beforeMemory wordAddress := by
  unfold Memory.read32
  rw [frame wordAddress (by simpa using outside 0 (by omega))]
  rw [frame (wordAddress + BitVec.ofNat 32 1) (outside 1 (by omega))]
  rw [frame (wordAddress + BitVec.ofNat 32 2) (outside 2 (by omega))]
  rw [frame (wordAddress + BitVec.ofNat 32 3) (outside 3 (by omega))]

theorem programLookupNativeFrame_preservesRead32
    (stackPointer : Word) (beforeMemory afterMemory : Memory)
    (frame : MemoryAgreesOutside (programLookupFrameFootprint stackPointer)
      afterMemory beforeMemory)
    (suffixOffset : Nat) (suffixEnd : suffixOffset + 4 <= 8) :
    Memory.read32 afterMemory (stackPointer + word32 suffixOffset) =
      Memory.read32 beforeMemory (stackPointer + word32 suffixOffset) := by
  have address (extra : Nat) :
      (stackPointer + word32 suffixOffset) + word32 extra =
        stackPointer + word32 (suffixOffset + extra) := by
    simp [word32, BitVec.add_assoc, ← BitVec.ofNat_add]
  have outside (extra : Nat) (extraBefore : suffixOffset + extra < 8) :
      ¬ programLookupFrameFootprint stackPointer
        (stackPointer + word32 (suffixOffset + extra)) := by
    intro inside
    rcases inside with ⟨frameOffset, frameBefore, overlap⟩
    exact programLookupFrameAvoidsStackSuffix stackPointer frameOffset
      (suffixOffset + extra) frameBefore extraBefore overlap
  unfold Memory.read32
  rw [frame (stackPointer + word32 suffixOffset) (outside 0 (by omega))]
  have address1 :
      (stackPointer + word32 suffixOffset) + BitVec.ofNat 32 1 =
        stackPointer + word32 (suffixOffset + 1) := by
    simpa [word32] using address 1
  have address2 :
      (stackPointer + word32 suffixOffset) + BitVec.ofNat 32 2 =
        stackPointer + word32 (suffixOffset + 2) := by
    simpa [word32] using address 2
  have address3 :
      (stackPointer + word32 suffixOffset) + BitVec.ofNat 32 3 =
        stackPointer + word32 (suffixOffset + 3) := by
    simpa [word32] using address 3
  rw [address1, frame _ (outside 1 (by omega))]
  rw [address2, frame _ (outside 2 (by omega))]
  rw [address3, frame _ (outside 3 (by omega))]

theorem programLookupNativePrologueResult_loopCutpoint
    (entry : ProgramLookupNativeLoadedEntry pe parameters records transferCount
      sourceRva before) :
    ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
      0 transferCount before
      (programLookupNativePrologueResult pe parameters before) := by
  have memoryExact :
      (programLookupNativePrologueResult pe parameters before).memory =
      programLookupNativePrologueMemory pe parameters before := by
    exact programLookupNativePrologueResult_memory pe parameters before
  have memoryFrame : MemoryAgreesOutside
      (programLookupFrameFootprint before.registers.esp)
      (programLookupNativePrologueResult pe parameters before).memory before.memory := by
    rw [memoryExact]
    exact programLookupNativePrologueMemory_frame pe parameters before
  refine {
    bounds := ⟨Nat.zero_le _, Nat.le_refl _⟩
    transferCountExact := entry.loaded.transferCountExact
    sourceFits := entry.loaded.sourceFits
    transferCountFits := entry.transferCountFits
    recordSourcesFit := entry.recordSourcesFit
    stackHasFrame := entry.loaded.stackHasFrame
    stackPointerExact := programLookupNativePrologueResult_esp pe parameters before
    framePointerExact := programLookupNativePrologueResult_ebp pe parameters before
    savedFramePointer := ?_
    returnAddressPreserved := ?_
    sourceArgumentPreserved := ?_
    lowSlotExact := ?_
    highSlotExact := ?_
    countLoaded := ?_
    tableLoaded := ?_
    frameDisjointFromCount := entry.frameDisjointFromCount
    frameDisjointFromTable := entry.frameDisjointFromTable
    memoryFrame
    preserved := programLookupNativePrologueResult_preserved pe parameters before
  }
  · rw [memoryExact]
    exact programLookupNativePrologueMemory_savedFramePointer entry
  · simpa [word32] using
      (programLookupNativeFrame_preservesRead32 before.registers.esp
        before.memory (programLookupNativePrologueResult pe parameters before).memory
        memoryFrame 0 (by omega))
  · exact (by
      calc
        Memory.read32
            (programLookupNativePrologueResult pe parameters before).memory
            (before.registers.esp + BitVec.ofNat 32 4) =
          Memory.read32 before.memory
            (before.registers.esp + BitVec.ofNat 32 4) := by
              simpa [word32] using
                (programLookupNativeFrame_preservesRead32 before.registers.esp
                  before.memory
                  (programLookupNativePrologueResult pe parameters before).memory
                  memoryFrame 4 (by omega))
        _ = BitVec.ofNat 32 sourceRva := entry.loaded.sourceArgumentLoaded)
  · rw [memoryExact]
    exact programLookupNativePrologueMemory_low entry
  · rw [memoryExact, programLookupNativePrologueMemory_high entry,
      entry.loaded.countLoaded]
  · rw [MemoryAgreesOutside.read32_of_bytesOutside memoryFrame]
    · exact entry.loaded.countLoaded
    · intro byte byteBefore inFrame
      rcases inFrame with ⟨frameOffset, frameBefore, addressExact⟩
      apply entry.frameDisjointFromCount frameOffset byte frameBefore byteBefore
      rw [← addressExact]
      simp [← BitVec.ofNat_add, Nat.add_assoc]
  · intro index record recordAt
    have indexBefore : index < records.length := by
      exact List.getElem?_eq_some_iff.mp
        (listAt?_eq_some_to_getElem?_eq_some records index record recordAt) |>.1
    rw [MemoryAgreesOutside.read32_of_bytesOutside memoryFrame]
    · exact entry.loaded.tableLoaded index record recordAt
    · intro byte byteBefore inFrame
      rcases inFrame with ⟨frameOffset, frameBefore, addressExact⟩
      apply entry.frameDisjointFromTable frameOffset index byte frameBefore
        indexBefore byteBefore
      rw [← addressExact]

theorem ProgramLookupNativeInstructionInventory.prologue
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (sourceRva : Nat) (before : MachineState)
    (entry : ProgramLookupNativeLoadedEntry pe parameters records transferCount
      sourceRva before) :
    exists state,
      runProgramLookupNativeFuel pe imports environment 7
        (.running parameters.entryRva 0 before [] 0 []) =
          .running (parameters.entryRva + 89) 0 state [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe parameters records transferCount sourceRva
        0 transferCount before state := by
  exact ⟨programLookupNativePrologueResult pe parameters before,
    inventory.runPrologueExact imports environment before,
    programLookupNativePrologueResult_loopCutpoint entry⟩

theorem ProgramLookupNativeReturnState.preservesLoadedSpan
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (before after : MachineState)
    (request : ABIRequestFacts abi (.programLookup records sourceRva) before)
    (returned : ProgramLookupNativeReturnState pe parameters records sourceRva
      before after)
    (span : Span) (loaded : LoadedSpanHolds pe relocations pe.imageBase span
      before.memory)
    (spanBounded : span.stop <= pe.sizeOfImage) :
    LoadedSpanHolds pe relocations pe.imageBase span after.memory := by
  intro offset offsetBefore expected decoded
  rw [returned.memoryFrame]
  · exact loaded offset offsetBefore expected decoded
  · simpa [word32, Nat.add_assoc] using
      (programLookupFrameAvoidsImage abi records sourceRva before request
        (span.start + offset) (by
          simp only [Span.stop] at spanBounded
          omega))

theorem ProgramLookupNativeReturnState.preservesImageRead32
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (before after : MachineState)
    (request : ABIRequestFacts abi (.programLookup records sourceRva) before)
    (returned : ProgramLookupNativeReturnState pe parameters records sourceRva
      before after)
    (rva : Nat) (bounded : rva + 4 <= pe.sizeOfImage) :
    Memory.read32 after.memory (word32 (pe.imageBase + rva)) =
      Memory.read32 before.memory (word32 (pe.imageBase + rva)) := by
  unfold Memory.read32
  have address (extra : Nat) :
      word32 (pe.imageBase + rva) + word32 extra =
        word32 (pe.imageBase + (rva + extra)) := by
    simp [word32, ← BitVec.ofNat_add, Nat.add_assoc]
  rw [returned.memoryFrame]
  · have address1 :
        word32 (pe.imageBase + rva) + BitVec.ofNat 32 1 =
          word32 (pe.imageBase + (rva + 1)) := by
      simpa [word32] using address 1
    have address2 :
        word32 (pe.imageBase + rva) + BitVec.ofNat 32 2 =
          word32 (pe.imageBase + (rva + 2)) := by
      simpa [word32] using address 2
    have address3 :
        word32 (pe.imageBase + rva) + BitVec.ofNat 32 3 =
          word32 (pe.imageBase + (rva + 3)) := by
      simpa [word32] using address 3
    rw [address1, returned.memoryFrame]
    · rw [address2, returned.memoryFrame]
      · rw [address3, returned.memoryFrame]
        exact programLookupFrameAvoidsImage abi records sourceRva before request
          (rva + 3) (by omega)
      · exact programLookupFrameAvoidsImage abi records sourceRva before request
          (rva + 2) (by omega)
    · exact programLookupFrameAvoidsImage abi records sourceRva before request
        (rva + 1) (by omega)
  · exact programLookupFrameAvoidsImage abi records sourceRva before request rva
      (by omega)

theorem ProgramLookupNativeReturnState.responseFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupTemplateCertificate abi.program pe imports
      function)
    (tableExact : certificate.parameters.tableRva = tableOffset)
    (sourceRva : Nat) (before after : MachineState)
    (request : ABIRequestFacts abi (.programLookup records sourceRva) before)
    (returned : ProgramLookupNativeReturnState pe certificate.parameters records
      sourceRva before after) :
    ABIResponseFacts abi (.programLookup records sourceRva)
      (.programLookup
        (StageA.Relational.InterpreterKernel.lookupProgramRecord records sourceRva))
      after [] := by
  have cdecl := request.cdecl
  change CDeclEntryFrameHolds abi (.programLookup records sourceRva) before at cdecl
  rcases cdecl with ⟨espExact, preserved, words, stackRange⟩
  have espExact' : before.registers.esp =
      abi.parameters.entryEsp abi.engineLayout .programLookup := by
    simpa only [AbstractKernelRequest.operation] using espExact
  simp only [AbstractKernelRequest.operation, requestArguments, WordsAt] at words
  refine {
    cdecl := ?_
    directionFlagClear := returned.directionFlagPreserved.trans
      request.directionFlagClear
    candidateImage := ?_
    originalProgramTable := ?_
    payload := ?_
  }
  · unfold CDeclReturnFrameHolds
    simp only [AbstractKernelRequest.operation, requestArguments, WordsAt]
    constructor
    · rw [returned.stackPopped, espExact']
      rfl
    constructor
    · rcases preserved with ⟨ebx, esi, edi, ebp⟩
      exact ⟨returned.ebxPreserved.trans ebx,
        returned.esiPreserved.trans esi, returned.ediPreserved.trans edi,
        returned.framePointerRestored.trans ebp⟩
    constructor
    · rw [← espExact']
      have preservedRead := programLookupNativeFrame_preservesRead32
        before.registers.esp before.memory after.memory returned.memoryFrame 0
        (by omega)
      simp [word32] at preservedRead
      rw [preservedRead, espExact']
      exact words.1
    constructor
    · rw [← espExact']
      rw [programLookupNativeFrame_preservesRead32 before.registers.esp
        before.memory after.memory returned.memoryFrame 4 (by omega)]
      rw [espExact']
      exact words.2.1
    · trivial
  · intro rva size bytes immutable offset expected offsetBefore indexed
    rw [returned.memoryFrame]
    · exact request.candidateImage rva size bytes immutable offset expected
        offsetBefore indexed
    · simpa [Nat.add_assoc] using
        (programLookupFrameAvoidsImage abi records sourceRva before request
          (rva + offset) (by
            have bounded := immutableRvaBytes_bounded immutable
            omega))
  · refine {
      tableSpan := ?_
      countSpan := ?_
      countWord := ?_
      sourceWords := ?_
    }
    · apply returned.preservesLoadedSpan abi sourceRva before after request
        abi.tableSpan request.originalProgramTable.tableSpan
      let facts := ConcreteKernelABI.programLookupStaticFacts abi
      simpa [ConcreteKernelABI.tableSpan, Span.stop] using facts.tableBounded
    · apply returned.preservesLoadedSpan abi sourceRva before after request
        abi.countSpan request.originalProgramTable.countSpan
      let facts := ConcreteKernelABI.programLookupStaticFacts abi
      simpa [ConcreteKernelABI.countSpan, Span.stop] using facts.countBounded
    · rw [returned.preservesImageRead32 abi sourceRva before after request
        countOffset]
      · exact request.originalProgramTable.countWord
      · exact (ConcreteKernelABI.programLookupStaticFacts abi).countBounded
    · intro index record recordAt
      have indexBefore : index < records.length :=
        List.getElem?_eq_some_iff.mp recordAt |>.1
      rw [Nat.add_assoc pe.imageBase tableOffset
        (index * transferRecordSize)]
      rw [returned.preservesImageRead32 abi sourceRva before after request
        (tableOffset + index * transferRecordSize)]
      · simpa [Nat.add_assoc] using
          request.originalProgramTable.sourceWords index record recordAt
      · let facts := ConcreteKernelABI.programLookupStaticFacts abi
        have tableBounded := facts.tableBounded
        have transferCountExact :=
          programTableCertificate_transferCount_eq_records_length
            abi.tableCertificate
        simp only [transferRecordSize] at tableBounded ⊢
        omega
  · change after.registers.eax =
        lookupResultPointer records pe.imageBase tableOffset sourceRva ∧
      ([] : List NativeExternalEvent) = []
    constructor
    · rw [returned.eaxExact, tableExact]
      rfl
    · rfl

/-- Precise local proof frontier.  Every equation executes a fixed contiguous
instruction chunk in the exact native machine.  The loop cases return to the
same checked cutpoint and the only terminal equation is the three-instruction
epilogue. -/
structure ProgramLookupNativeLocalSemantics
    (pe : PE32) (imports : List PEImport) (environment : NativeEnvironment)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount : Nat)
    (certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function) : Prop where
  prologue : forall sourceRva before,
    ProgramLookupNativeLoadedEntry pe certificate.template.parameters records
      transferCount sourceRva before ->
    exists state,
      runProgramLookupNativeFuel pe imports environment 7
        (.running certificate.template.parameters.entryRva 0 before [] 0 []) =
          .running (certificate.template.parameters.entryRva + 89) 0 state [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
        transferCount sourceRva 0 transferCount before state
  lowerIteration : forall sourceRva before state low high midpoint record,
    ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
      transferCount sourceRva low high before state ->
    forall undefinedSlot,
    low < high -> midpoint = low + (high - low) / 2 ->
    listAt? records midpoint = some record -> record.sourceRva < sourceRva ->
    exists nextState,
      runProgramLookupNativeFuel pe imports environment 25
        (.running (certificate.template.parameters.entryRva + 89) undefinedSlot
          state [] 0 []) =
          .running (certificate.template.parameters.entryRva + 89) 0
            nextState [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
        transferCount sourceRva (midpoint + 1) high before nextState
  upperIteration : forall sourceRva before state low high midpoint record,
    ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
      transferCount sourceRva low high before state ->
    forall undefinedSlot,
    low < high -> midpoint = low + (high - low) / 2 ->
    listAt? records midpoint = some record -> ¬ record.sourceRva < sourceRva ->
    exists nextState,
      runProgramLookupNativeFuel pe imports environment 23
        (.running (certificate.template.parameters.entryRva + 89) undefinedSlot
          state [] 0 []) =
          .running (certificate.template.parameters.entryRva + 89) 2
            nextState [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
        transferCount sourceRva low midpoint before nextState
  finish : forall sourceRva before state index undefinedSlot,
    ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
      transferCount sourceRva index index before state ->
    ReflectedProgramLookupTrace records sourceRva 0 transferCount index ->
    exists fuel epilogueSlot epilogueState,
      0 < fuel /\ fuel <= 22 /\
      runProgramLookupNativeFuel pe imports environment fuel
        (.running (certificate.template.parameters.entryRva + 89) undefinedSlot
          state [] 0 []) =
          .running (certificate.template.parameters.entryRva + 157) epilogueSlot
            epilogueState [] 0 [] /\
      ProgramLookupNativeEpilogueCutpoint pe certificate.template.parameters
        records sourceRva before epilogueState
  epilogue : forall sourceRva before state undefinedSlot,
    ProgramLookupNativeEpilogueCutpoint pe certificate.template.parameters
      records sourceRva before state ->
    exists after,
      runProgramLookupNativeFuel pe imports environment 3
        (.running (certificate.template.parameters.entryRva + 157) undefinedSlot
          state [] 0 []) =
          .returned after [] /\
      ProgramLookupNativeReturnState pe certificate.template.parameters records
        sourceRva before after

theorem ProgramLookupNativeInstructionInventory.prologueLaw
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    [ProgramLookupNativeAddressBounds parameters]
    (sourceRva : Nat) (before : MachineState)
    (entry : ProgramLookupNativeLoadedEntry pe parameters
      records transferCount sourceRva before) :
    exists state,
      runProgramLookupNativeFuel pe imports environment 7
        (.running parameters.entryRva 0 before [] 0 []) =
          .running (parameters.entryRva + 89) 0 state [] 0 [] /\
      ProgramLookupNativeLoopCutpoint pe parameters records
        transferCount sourceRva 0 transferCount before state := by
  exact inventory.prologue imports environment sourceRva before entry

theorem ProgramLookupNativeInstructionInventory.epilogueLaw
    (inventory : ProgramLookupNativeInstructionInventory pe parameters)
    (imports : List PEImport) (environment : NativeEnvironment)
    (sourceRva : Nat) (before state : MachineState) (undefinedSlot : Nat)
    (cutpoint : ProgramLookupNativeEpilogueCutpoint pe parameters records
      sourceRva before state) :
    exists after,
      runProgramLookupNativeFuel pe imports environment 3
        (.running (parameters.entryRva + 157) undefinedSlot
          state [] 0 []) = .returned after [] /\
      ProgramLookupNativeReturnState pe parameters records sourceRva before
        after := by
  exact inventory.epilogue imports environment sourceRva before state
    undefinedSlot cutpoint

/-- Assemble the public local-semantics record from the checked instruction
inventory.  No execution law remains caller supplied. -/
def programLookupNativeLocalSemantics
    (certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function)
    (inventory : ProgramLookupNativeInstructionInventory pe
      certificate.template.parameters)
    (environment : NativeEnvironment)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (recordsSorted : sourceRvasStrictlySorted records)
    (transferCount : Nat) :
    ProgramLookupNativeLocalSemantics pe imports environment records transferCount
      certificate := by
  letI : ProgramLookupNativeAddressBounds certificate.template.parameters := {
    entryEndBounded := certificate.entryEndBounded
  }
  exact {
  prologue := by
    intro sourceRva before entry
    exact inventory.prologueLaw imports environment sourceRva before entry
  lowerIteration := by
    intro sourceRva before state low high midpoint record cutpoint undefinedSlot
      notConverged midpointExact recordAt recordLess
    exact inventory.lowerIterationLaw imports environment records transferCount
      sourceRva low high midpoint record before state cutpoint undefinedSlot
      notConverged midpointExact recordAt recordLess
  upperIteration := by
    intro sourceRva before state low high midpoint record cutpoint undefinedSlot
      notConverged midpointExact recordAt recordNotLess
    exact inventory.upperIterationLaw imports environment records transferCount
      sourceRva low high midpoint record before state cutpoint undefinedSlot
      notConverged midpointExact recordAt recordNotLess
  finish := by
    intro sourceRva before state index undefinedSlot cutpoint trace
    exact inventory.finishLaw imports environment records recordsSorted transferCount
      sourceRva index undefinedSlot before state cutpoint trace
  epilogue := by
    intro sourceRva before state undefinedSlot cutpoint
    exact inventory.epilogueLaw imports environment sourceRva before state
      undefinedSlot cutpoint
  }

/-- Candidate ABI interpretation of native return facts.  It contains no
execution premise or final-state constructor. -/
structure ProgramLookupNativeConcreteABI
    (pe : PE32) (abi : KernelABIRelation)
    (records : List StageA.Relational.Interpreter.ProgramRecord)
    (transferCount : Nat)
    (certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function) : Prop where
  requestEntry : forall requestRecords sourceRva before,
    abi.requestRelated (.programLookup requestRecords sourceRva) before ->
      requestRecords = records /\
      Nonempty (ProgramLookupNativeLoadedEntry pe
        certificate.template.parameters records transferCount sourceRva before)
  responseExit : forall sourceRva before after,
    abi.requestRelated (.programLookup records sourceRva) before ->
    ProgramLookupNativeReturnState pe certificate.template.parameters records
      sourceRva before after ->
    abi.responseRelated (.programLookup records sourceRva)
      (.programLookup
        (StageA.Relational.InterpreterKernel.lookupProgramRecord records sourceRva))
      after []
  scratchContainsFrame : forall sourceRva before address,
    abi.requestRelated (.programLookup records sourceRva) before ->
    ProgramLookupNativeLoadedEntry pe certificate.template.parameters records
      transferCount sourceRva before ->
    programLookupFrameFootprint before.registers.esp address ->
      abi.scratchFootprint (.programLookup records sourceRva) address

noncomputable def programLookupNativeConcreteABI
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupNativeTemplateCertificate abi.program pe imports
      function)
    (tableExact : certificate.template.parameters.tableRva = tableOffset)
    (countExact : certificate.template.parameters.countRva = countOffset)
    (recordSourcesFit : programLookupRecordSourcesFit records = true) :
    ProgramLookupNativeConcreteABI pe (ConcreteKernelABI.relation abi) records
      abi.tableCertificate.transferCount certificate := {
  requestEntry := by
    intro requestRecords sourceRva before related
    change ABIRequestFacts abi (.programLookup requestRecords sourceRva) before
      at related
    have recordsExact : requestRecords = records := related.payload.1
    subst requestRecords
    let invocation := concreteProgramLookupInvocation abi certificate.template
      tableExact countExact sourceRva before related
    refine ⟨rfl, ⟨{
      loaded := invocation.entry.loaded
      transferCountFits := ?_
      recordSourcesFit
      frameDisjointFromCount := ?_
      frameDisjointFromTable := ?_
    }⟩⟩
    · let facts := ConcreteKernelABI.programLookupStaticFacts abi
      have tableBounded := facts.tableBounded
      have imageBounded := facts.imageBounded
      simp only [transferRecordSize] at tableBounded
      omega
    intro frameOffset byteOffset frameBefore byteBefore overlap
    have inFrame : programLookupFrameFootprint before.registers.esp
        (programLookupFrameByte before.registers.esp frameOffset) :=
      ⟨frameOffset, frameBefore, rfl⟩
    have countBefore : countOffset + byteOffset < pe.sizeOfImage := by
      have bounded := (ConcreteKernelABI.programLookupStaticFacts abi).countBounded
      omega
    have countAddressExact :
        word32 (pe.imageBase + (countOffset + byteOffset)) =
          programLookupFrameByte before.registers.esp frameOffset := by
      rw [← countExact]
      simpa [word32, Nat.add_assoc] using overlap.symm
    apply programLookupFrameAvoidsImage abi records sourceRva before related
      (countOffset + byteOffset) countBefore
    rw [countAddressExact]
    exact inFrame
    intro frameOffset tableIndex byteOffset frameBefore indexBefore byteBefore overlap
    have inFrame : programLookupFrameFootprint before.registers.esp
        (programLookupFrameByte before.registers.esp frameOffset) :=
      ⟨frameOffset, frameBefore, rfl⟩
    have tableByteBefore :
        tableOffset + tableIndex * transferRecordSize + byteOffset < pe.sizeOfImage := by
      let facts := ConcreteKernelABI.programLookupStaticFacts abi
      have tableBounded := facts.tableBounded
      have transferCountExact :=
        programTableCertificate_transferCount_eq_records_length abi.tableCertificate
      simp only [transferRecordSize] at tableBounded ⊢
      omega
    have tableAddressExact :
        word32 (pe.imageBase +
          (tableOffset + tableIndex * transferRecordSize + byteOffset)) =
          programLookupFrameByte before.registers.esp frameOffset := by
      rw [← tableExact]
      simpa [programLookupTableAddress, word32, Nat.add_assoc,
        ← BitVec.ofNat_add] using overlap.symm
    apply programLookupFrameAvoidsImage abi records sourceRva before related
      (tableOffset + tableIndex * transferRecordSize + byteOffset)
      tableByteBefore
    rw [tableAddressExact]
    exact inFrame
  responseExit := by
    intro sourceRva before after related returned
    change ABIRequestFacts abi (.programLookup records sourceRva) before at related
    exact returned.responseFacts abi certificate.template tableExact sourceRva
      before after related
  scratchContainsFrame := by
    intro sourceRva before address related loaded inFrame
    change ABIRequestFacts abi (.programLookup records sourceRva) before at related
    change addressInSpan abi.parameters.writableWorkspace address
    exact programLookupFrameInWorkspace abi records sourceRva before related address
      inFrame
}

theorem ProgramLookupNativeLocalSemantics.traceToLoopExit
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {environment : NativeEnvironment}
    {records : List StageA.Relational.Interpreter.ProgramRecord}
    {transferCount sourceRva low high resultIndex undefinedSlot : Nat}
    {before state : MachineState}
    {certificate : ProgramLookupNativeTemplateCertificate program pe imports function}
    (semantics : ProgramLookupNativeLocalSemantics pe imports environment records
      transferCount certificate)
    (trace : ReflectedProgramLookupTrace records sourceRva low high resultIndex)
    (cutpoint : ProgramLookupNativeLoopCutpoint pe
      certificate.template.parameters records transferCount sourceRva low high
      before state) :
    exists resultSlot resultState,
      NativeSteps pe imports environment
        (.running (certificate.template.parameters.entryRva + 89) undefinedSlot
          state [] 0 [])
        (.running (certificate.template.parameters.entryRva + 89) resultSlot
          resultState [] 0 []) /\
      ProgramLookupNativeLoopCutpoint pe certificate.template.parameters records
        transferCount sourceRva resultIndex resultIndex before resultState := by
  induction trace generalizing state undefinedSlot with
  | done index invariant =>
      exact ⟨undefinedSlot, state, .refl _, cutpoint⟩
  | lower low high midpoint resultIndex record invariantBefore notConverged
      midpointExact recordAt recordLess invariantAfter rankDecreases rest induction =>
      obtain ⟨nextState, chunkExact, nextCutpoint⟩ :=
        semantics.lowerIteration sourceRva before state low high midpoint record
          cutpoint undefinedSlot notConverged midpointExact recordAt recordLess
      have chunkSteps := runProgramLookupNativeFuel_steps pe imports environment 25
        (.running (certificate.template.parameters.entryRva + 89) undefinedSlot
          state [] 0 [])
      rw [chunkExact] at chunkSteps
      obtain ⟨resultSlot, resultState, restSteps, resultCutpoint⟩ :=
        induction nextCutpoint
      exact ⟨resultSlot, resultState, chunkSteps.trans restSteps, resultCutpoint⟩
  | upper low high midpoint resultIndex record invariantBefore notConverged
      midpointExact recordAt recordNotLess invariantAfter rankDecreases rest induction =>
      obtain ⟨nextState, chunkExact, nextCutpoint⟩ :=
        semantics.upperIteration sourceRva before state low high midpoint record
          cutpoint undefinedSlot notConverged midpointExact recordAt recordNotLess
      have chunkSteps := runProgramLookupNativeFuel_steps pe imports environment 23
        (.running (certificate.template.parameters.entryRva + 89) undefinedSlot
          state [] 0 [])
      rw [chunkExact] at chunkSteps
      obtain ⟨resultSlot, resultState, restSteps, resultCutpoint⟩ :=
        induction nextCutpoint
      exact ⟨resultSlot, resultState, chunkSteps.trans restSteps, resultCutpoint⟩

/-- Conditional native closure from strictly local exact-instruction laws.
Neither the native path nor its final state is supplied by the caller. -/
theorem ProgramLookupNativeLocalSemantics.constructsNativeDispatch
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {environment : NativeEnvironment}
    {records : List StageA.Relational.Interpreter.ProgramRecord}
    {transferCount sourceRva resultIndex : Nat}
    {before : MachineState}
    {certificate : ProgramLookupNativeTemplateCertificate program pe imports function}
    (semantics : ProgramLookupNativeLocalSemantics pe imports environment records
      transferCount certificate)
    (entry : ProgramLookupNativeLoadedEntry pe certificate.template.parameters
      records transferCount sourceRva before)
    (trace : ReflectedProgramLookupTrace records sourceRva 0 transferCount
      resultIndex) :
    exists after,
      NativeDispatches pe imports environment
        certificate.template.parameters.entryRva before after [] /\
      ProgramLookupNativeReturnState pe certificate.template.parameters records
        sourceRva before after := by
  obtain ⟨loopState, prologueExact, loopCutpoint⟩ :=
    semantics.prologue sourceRva before entry
  have prologueSteps := runProgramLookupNativeFuel_steps pe imports environment 7
    (.running certificate.template.parameters.entryRva 0 before [] 0 [])
  rw [prologueExact] at prologueSteps
  obtain ⟨resultSlot, resultState, loopSteps, resultCutpoint⟩ :=
    semantics.traceToLoopExit trace loopCutpoint
  obtain ⟨finishFuel, epilogueSlot, epilogueState, finishPositive, finishBound,
    finishExact, epilogueCutpoint⟩ :=
      semantics.finish sourceRva before resultState resultIndex resultSlot
        resultCutpoint trace
  have finishSteps := runProgramLookupNativeFuel_steps pe imports environment
    finishFuel
    (.running (certificate.template.parameters.entryRva + 89) resultSlot
      resultState [] 0 [])
  rw [finishExact] at finishSteps
  obtain ⟨after, epilogueExact, returnState⟩ :=
    semantics.epilogue sourceRva before epilogueState epilogueSlot
      epilogueCutpoint
  have epilogueSteps := runProgramLookupNativeFuel_steps pe imports environment 3
    (.running (certificate.template.parameters.entryRva + 157) epilogueSlot
      epilogueState [] 0 [])
  rw [epilogueExact] at epilogueSteps
  exact ⟨after,
    prologueSteps.trans (loopSteps.trans (finishSteps.trans epilogueSteps)),
    returnState⟩

/-- Compose the exact local chunk laws into the public operation theorem.
The only execution premises are the bounded prologue, loop-arm, finish, and
epilogue laws in `ProgramLookupNativeLocalSemantics`; neither a complete path
nor a final state is accepted from generated code. -/
theorem ProgramLookupNativeLocalSemantics.programLookupRefinesUsingNative
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {environment : NativeEnvironment}
    {abi : KernelABIRelation}
    {records : List StageA.Relational.Interpreter.ProgramRecord}
    {transferCount : Nat}
    {certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function}
    (semantics : ProgramLookupNativeLocalSemantics pe imports environment records
      transferCount certificate)
    (concreteABI : ProgramLookupNativeConcreteABI pe abi records transferCount
      certificate)
    (entryRvaExact : program.functionEntry? .programLookup =
      some certificate.template.parameters.entryRva) :
    KernelOperationRefinesUsing program abi
      (NativeDispatches pe imports environment) .programLookup := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup requestRecords sourceRva =>
      obtain ⟨recordsExact, ⟨entry⟩⟩ :=
        concreteABI.requestEntry requestRecords sourceRva before requestRelated
      subst requestRecords
      cases transition
      obtain ⟨resultIndex, trace⟩ := reflectedProgramLookupTrace_exists records
        sourceRva 0 transferCount (by
          rw [entry.loaded.transferCountExact]
          omega)
      obtain ⟨after, nativeDispatch, returnState⟩ :=
        semantics.constructsNativeDispatch entry trace
      refine ⟨certificate.template.parameters.entryRva, after, [],
        entryRvaExact, nativeDispatch,
        concreteABI.responseExit sourceRva before after requestRelated returnState,
        ?_⟩
      intro address outsideScratch
      apply returnState.memoryFrame address
      intro inFrame
      exact outsideScratch
        (concreteABI.scratchContainsFrame sourceRva before address requestRelated
          entry inFrame)
  | interpreterStep records requestEnvironment sourceRva state =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records requestEnvironment resolveCodeTarget sourceRva state =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records requestEnvironment resolveCodeTarget event state =>
      simp [AbstractKernelRequest.operation] at operationMatches

#print axioms runProgramLookupNativeFuel_stepsN
#print axioms runProgramLookupNativeWorldFuel_path
#print axioms ProgramLookupNativeReturnState.responseFacts
#print axioms programLookupNativeConcreteABI
#print axioms ProgramLookupNativeLocalSemantics.traceToLoopExit
#print axioms ProgramLookupNativeLocalSemantics.constructsNativeDispatch
#print axioms programLookupTemplateCertificateToNative
#print axioms ProgramLookupNativeLocalSemantics.programLookupRefinesUsingNative

end StageA.Relational.InterpreterKernelLookupNative
