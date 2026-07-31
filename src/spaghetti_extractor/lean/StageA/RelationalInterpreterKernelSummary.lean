import StageA.RelationalInterpreterKernelData
import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterKernelLoop
import StageA.RelationalInterpreterKernelProgramIndex
import StageA.RelationalSymbolicSoundness

namespace StageA.Relational.InterpreterKernelSummary

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelLoop
open StageA.Relational.InterpreterKernelProgramIndex
open StageA.Relational.SymbolicSoundness

export StageA.Relational.InterpreterKernelProgramIndex (
  sourceRvasStrictlySorted
  lookupProgramRecordWithIndexAux
  lookupProgramRecordWithIndex?
  lookupProgramRecordIndex?
  lookupProgramRecordWithIndexAux_recordExact
)

/-- Compatibility projection for the executable-kernel lookup.  The data and
execution kernels intentionally keep separate definitions of the same `find?`
operation; their equality is definitional and proved once here. -/
theorem lookupProgramRecordWithIndex?_recordExact
    (records : List ProgramRecord) (sourceRva : Nat) :
    (lookupProgramRecordWithIndex? records sourceRva).map Prod.snd =
      StageA.Relational.InterpreterKernel.lookupProgramRecord records
        sourceRva := by
  simpa [StageA.Relational.InterpreterKernelData.lookupProgramRecord,
    StageA.Relational.InterpreterKernel.lookupProgramRecord] using
    StageA.Relational.InterpreterKernelProgramIndex.lookupProgramRecordWithIndex?_recordExact
      records sourceRva

/-!
Generic function-summary contract for the compiled `programLookup` operation.
The contract is candidate-parametric: executable RVAs, table RVAs, relocation
records, decoded instructions, and ABI layouts are all explicit parameters.
Generated data can propose those parameters, but cannot manufacture any of the
proposition-valued simulation fields below.
-/

structure ProgramLookupTemplateParameters where
  entryRva : Nat
  tableRva : Nat
  countRva : Nat
deriving Repr, DecidableEq

def pe32U32Bytes (value : Nat) : Bytes :=
  [value % 256, (value / 256) % 256, (value / 65536) % 256,
    (value / 16777216) % 256]

/-- Exact 161-byte O0 cdecl lower-bound template.  Only the two PE data
addresses vary; all control displacements, frame slots, scaling operations,
and return instructions are fixed. -/
def programLookupTemplateBytes (pe : PE32)
    (parameters : ProgramLookupTemplateParameters) : Bytes :=
  let count := pe32U32Bytes (pe.imageBase + parameters.countRva)
  let table := pe32U32Bytes (pe.imageBase + parameters.tableRva)
  [0x55, 0x89, 0xe5, 0x83, 0xec, 0x10, 0xc7, 0x45, 0xfc,
    0, 0, 0, 0, 0xa1] ++ count ++
  [0x89, 0x45, 0xf8, 0xeb, 0x42,
   0x8b, 0x45, 0xf8, 0x2b, 0x45, 0xfc, 0xd1, 0xe8, 0x89, 0xc2,
   0x8b, 0x45, 0xfc, 0x01, 0xd0, 0x89, 0x45, 0xf4,
   0x8b, 0x55, 0xf4, 0x89, 0xd0, 0xc1, 0xe0, 0x02, 0x01, 0xd0,
   0xc1, 0xe0, 0x03, 0x05] ++ table ++
  [0x8b, 0x00, 0x89, 0x45, 0xf0, 0x8b, 0x45, 0xf0,
   0x3b, 0x45, 0x08, 0x73, 0x0b,
   0x8b, 0x45, 0xf4, 0x83, 0xc0, 0x01, 0x89, 0x45, 0xfc, 0xeb, 0x06,
   0x8b, 0x45, 0xf4, 0x89, 0x45, 0xf8,
   0x8b, 0x45, 0xfc, 0x3b, 0x45, 0xf8, 0x72, 0xb6,
   0xa1] ++ count ++
  [0x39, 0x45, 0xfc, 0x73, 0x2d,
   0x8b, 0x55, 0xfc, 0x89, 0xd0, 0xc1, 0xe0, 0x02, 0x01, 0xd0,
   0xc1, 0xe0, 0x03, 0x05] ++ table ++
  [0x8b, 0x00, 0x39, 0x45, 0x08, 0x75, 0x14,
   0x8b, 0x55, 0xfc, 0x89, 0xd0, 0xc1, 0xe0, 0x02, 0x01, 0xd0,
   0xc1, 0xe0, 0x03, 0x05] ++ table ++
  [0xeb, 0x05, 0xb8, 0, 0, 0, 0, 0xc9, 0x31, 0xd2, 0xc3]

structure ProgramLookupRelativeBlockShape where
  entryOffset : Nat
  successorOffsets : List Nat
  instructionOffsets : List Nat
deriving Repr, DecidableEq

def programLookupTemplateBlockShapes :
    List ProgramLookupRelativeBlockShape := [
  { entryOffset := 0, successorOffsets := [89]
    instructionOffsets := [0, 1, 3, 6, 13, 18, 21] },
  { entryOffset := 23, successorOffsets := [83, 72]
    instructionOffsets :=
      [23, 26, 29, 31, 33, 36, 38, 41, 44, 46, 49, 51, 54, 59,
        61, 64, 67, 70] },
  { entryOffset := 72, successorOffsets := [89]
    instructionOffsets := [72, 75, 78, 81] },
  { entryOffset := 83, successorOffsets := [89]
    instructionOffsets := [83, 86] },
  { entryOffset := 89, successorOffsets := [23, 97]
    instructionOffsets := [89, 92, 95] },
  { entryOffset := 97, successorOffsets := [152, 107]
    instructionOffsets := [97, 102, 105] },
  { entryOffset := 107, successorOffsets := [152, 132]
    instructionOffsets := [107, 110, 112, 115, 117, 120, 125, 127, 130] },
  { entryOffset := 132, successorOffsets := [157]
    instructionOffsets := [132, 135, 137, 140, 142, 145, 150] },
  { entryOffset := 152, successorOffsets := [157]
    instructionOffsets := [152] },
  { entryOffset := 157, successorOffsets := []
    instructionOffsets := [157, 158, 160] }
]

def ProgramLookupRelativeBlockShape.matches (entryRva : Nat)
    (shape : ProgramLookupRelativeBlockShape) (block : KernelBlock) : Bool :=
  entryRva <= block.entryRva &&
    block.entryRva - entryRva == shape.entryOffset &&
    block.successors.all (entryRva <= ·) &&
    block.successors.map (· - entryRva) == shape.successorOffsets &&
    block.instructions.all (fun instruction => entryRva <= instruction.rva) &&
    block.instructions.map (fun instruction => instruction.rva - entryRva) ==
      shape.instructionOffsets

structure ReflectedProgramLookupTemplate where
  instructions : List (KernelInstruction × DecodedInstruction)
deriving Repr, DecidableEq

def reflectProgramLookupTemplate? (pe : PE32)
    (function : KernelFunction) : Option ReflectedProgramLookupTemplate := do
  let instructions <- function.instructions.mapM fun instruction => do
    let decoded <- instruction.decode? pe
    pure (instruction, decoded)
  pure { instructions }

/-- Fully reflected finite template check.  Exact candidate bytes imply the
instruction forms, while `reflectProgramLookupTemplate?` records the exact
authoritative decoder sequence and the relative-shape check fixes every CFG
edge and instruction boundary without fixing an image RVA. -/
def programLookupTemplateChecked (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) (function : KernelFunction)
    (parameters : ProgramLookupTemplateParameters) : Bool :=
  function ∈ program.functions &&
    function.role == .programLookup &&
    function.span.start == parameters.entryRva &&
    function.span.size == 161 &&
    function.bytes == programLookupTemplateBytes pe parameters &&
    function.x87Frames.isEmpty && function.padding.isEmpty &&
    function.checked pe imports &&
    (reflectProgramLookupTemplate? pe function).isSome &&
    function.blocks.length == programLookupTemplateBlockShapes.length &&
    (List.zip programLookupTemplateBlockShapes function.blocks).all
      (fun pair => pair.1.matches parameters.entryRva pair.2) &&
    parameters.tableRva % 4 == 0 && parameters.countRva % 4 == 0 &&
    pe.imageBase + parameters.tableRva < 2 ^ 32 &&
    pe.imageBase + parameters.countRva < 2 ^ 32

structure ProgramLookupTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  parameters : ProgramLookupTemplateParameters
  reflection : ReflectedProgramLookupTemplate
  reflected :
    reflectProgramLookupTemplate? pe function = some reflection
  checked :
    programLookupTemplateChecked program pe imports function parameters = true

/-- Candidate-specific projection of binary-search bounds from native states.
The source key is explicit because an ABI is free to keep it in a register,
stack slot, or other candidate-specific location. -/
structure ProgramLookupStateView where
  low : Nat -> NativeExecution -> Nat
  high : Nat -> NativeExecution -> Nat

def BinarySearchInvariant (transferCount sourceRva : Nat)
    (view : ProgramLookupStateView) (state : NativeExecution) : Prop :=
  view.low sourceRva state <= view.high sourceRva state /\
    view.high sourceRva state <= transferCount

/-- The termination rank is definitionally the binary-search interval width. -/
def BinarySearchRank (sourceRva : Nat) (view : ProgramLookupStateView)
    (state : NativeExecution) : Nat :=
  view.high sourceRva state - view.low sourceRva state

theorem BinarySearchRank.eq_high_sub_low
    (sourceRva : Nat) (view : ProgramLookupStateView)
    (state : NativeExecution) :
    BinarySearchRank sourceRva view state =
      view.high sourceRva state - view.low sourceRva state :=
  rfl

def programLookupInitialExecution (entryRva : Nat)
    (before : MachineState) : NativeExecution :=
  .running entryRva 0 before [] 0 []

/-- The ABI request must establish the real function entry and initial bounds.
It also prevents an ABI relation from silently substituting a different
semantic program. -/
structure ProgramLookupEntryInvariant
    (semanticRecords records : List ProgramRecord)
    (transferCount entryRva sourceRva : Nat)
    (view : ProgramLookupStateView) (before : MachineState) : Prop where
  recordsExact : records = semanticRecords
  atFunctionEntry :
    executionAtRva (programLookupInitialExecution entryRva before) entryRva
  lowIsZero :
    view.low sourceRva (programLookupInitialExecution entryRva before) = 0
  highIsTransferCount :
    view.high sourceRva (programLookupInitialExecution entryRva before) =
      transferCount
  bounds : BinarySearchInvariant transferCount sourceRva view
    (programLookupInitialExecution entryRva before)

/-- A nonterminal exact-CFG path.  Keeping this separate from terminal CFG
execution permits loop iterations to be concatenated with a final return. -/
inductive ExactKernelCFGPath
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (targets : KernelIndirectTargetInventory) :
    NativeExecution -> NativeExecution -> Prop
  | refl (state) :
      ExactKernelCFGPath program pe imports environment targets state state
  | edge (before middle after) :
      ExactKernelEdgeStep program pe imports environment targets before middle ->
      ExactKernelCFGPath program pe imports environment targets middle after ->
      ExactKernelCFGPath program pe imports environment targets before after

theorem ExactKernelCFGPath.trans
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {before middle after : NativeExecution}
    (first : ExactKernelCFGPath program pe imports environment targets
      before middle)
    (second : ExactKernelCFGPath program pe imports environment targets
      middle after) :
    ExactKernelCFGPath program pe imports environment targets before after := by
  induction first with
  | refl => exact second
  | edge before next middle step rest induction =>
      exact .edge before next after step (induction second)

theorem ExactKernelCFGPath.thenExecution
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {before middle after : NativeExecution}
    (pathPrefix : ExactKernelCFGPath program pe imports environment targets
      before middle)
    (suffix : ExactKernelCFGExecution program pe imports environment targets
      middle after) :
    ExactKernelCFGExecution program pe imports environment targets before after := by
  induction pathPrefix with
  | refl => exact suffix
  | edge before next middle step rest induction =>
      exact .edge before next after step (induction suffix)

/-- Exact finite binary-search iterations.  Every iteration is an actual CFG
path, preserves `low <= high <= transferCount`, and strictly decreases the
definitionally fixed rank `high - low`.  The only terminal constructor requires
convergence. -/
inductive ProgramLookupLoopTrace
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (targets : KernelIndirectTargetInventory)
    (transferCount sourceRva : Nat) (view : ProgramLookupStateView) :
    NativeExecution -> NativeExecution -> Prop
  | done (state)
      (invariant : BinarySearchInvariant transferCount sourceRva view state)
      (converged : view.low sourceRva state = view.high sourceRva state) :
      ProgramLookupLoopTrace program pe imports environment targets
        transferCount sourceRva view state state
  | iterate (before next after)
      (invariantBefore :
        BinarySearchInvariant transferCount sourceRva view before)
      (iteration : ExactKernelCFGPath program pe imports environment targets
        before next)
      (invariantAfter :
        BinarySearchInvariant transferCount sourceRva view next)
      (rankDecreases :
        BinarySearchRank sourceRva view next <
          BinarySearchRank sourceRva view before)
      (rest : ProgramLookupLoopTrace program pe imports environment targets
        transferCount sourceRva view next after) :
      ProgramLookupLoopTrace program pe imports environment targets
        transferCount sourceRva view before after

theorem ProgramLookupLoopTrace.toExactCFGPath
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {targets : KernelIndirectTargetInventory}
    {transferCount sourceRva : Nat} {view : ProgramLookupStateView}
    {before after : NativeExecution}
    (trace : ProgramLookupLoopTrace program pe imports environment targets
      transferCount sourceRva view before after) :
    ExactKernelCFGPath program pe imports environment targets before after := by
  induction trace with
  | done state => exact .refl state
  | iterate before next after invariantBefore iteration invariantAfter
      rankDecreases rest induction =>
      exact iteration.trans induction

/-- Exact C ABI return value: null on a miss, otherwise the address of the
matching fixed-size record in the PE-backed table. -/
def programLookupReturnWord (pe : PE32) (tableRva : Nat)
    (records : List ProgramRecord) (sourceRva : Nat) : Word :=
  lookupResultPointer records pe.imageBase tableRva sourceRva

def programLookupFrameByte (stackPointer : Word) (offset : Nat) : Word :=
  stackPointer + BitVec.ofNat 32 (2 ^ 32 - 20 + offset)

def programLookupFrameFootprint (stackPointer : Word) : CandidateFootprint :=
  fun address => exists offset, offset < 20 /\
    address = programLookupFrameByte stackPointer offset

def programLookupTemplateFrameMemory (stackPointer : Word)
    (memory : Memory) : Memory :=
  fun address =>
    if (List.range 20).any fun offset =>
        address == programLookupFrameByte stackPointer offset then
      BitVec.ofNat 8 0
    else memory address

theorem programLookupTemplateFrameMemory_agreesOutside
    (stackPointer : Word) (memory : Memory) :
    MemoryAgreesOutside (programLookupFrameFootprint stackPointer)
      (programLookupTemplateFrameMemory stackPointer memory) memory := by
  intro address outside
  unfold programLookupTemplateFrameMemory
  generalize presentExact : (List.range 20).any fun offset =>
    address == programLookupFrameByte stackPointer offset = present
  cases present with
  | false => rfl
  | true =>
      exfalso
      simp only [List.any_eq_true] at presentExact
      obtain ⟨offset, offsetMember, addressExact⟩ := presentExact
      apply outside
      exact ⟨offset, List.mem_range.mp offsetMember, beq_iff_eq.mp addressExact⟩

def programLookupTableAddress (pe : PE32) (tableRva index : Nat) : Word :=
  BitVec.ofNat 32 (pe.imageBase + tableRva + index * transferRecordSize)

noncomputable def listAt?_witness_of_lt_length {Value : Type} (values : List Value)
    (index : Nat) (inside : index < values.length) :
    { value // listAt? values index = some value } := by
  induction values generalizing index with
  | nil => simp at inside
  | cons head tail induction =>
      cases index with
      | zero => exact ⟨head, rfl⟩
      | succ index =>
          simp only [List.length_cons, Nat.succ_lt_succ_iff] at inside
          exact induction index inside

theorem listAt?_exists_of_lt_length {Value : Type} (values : List Value)
    (index : Nat) (inside : index < values.length) :
    exists value, listAt? values index = some value :=
  let witness := listAt?_witness_of_lt_length values index inside
  ⟨witness.1, witness.2⟩

/-- Reflected control trace for the exact lower-bound loop.  Each constructor
records the table comparison performed by the machine template, preserves
`low <= high <= records.length`, and carries the strict decrease of the exact
rank `high - low`. -/
inductive ReflectedProgramLookupTrace (records : List ProgramRecord)
    (sourceRva : Nat) : Nat -> Nat -> Nat -> Prop
  | done (index)
      (invariant : index <= index /\ index <= records.length) :
      ReflectedProgramLookupTrace records sourceRva index index index
  | lower (low high midpoint resultIndex) (record : ProgramRecord)
      (invariantBefore : low <= high /\ high <= records.length)
      (notConverged : low < high)
      (midpointExact : midpoint = low + (high - low) / 2)
      (recordAt : listAt? records midpoint = some record)
      (recordLess : record.sourceRva < sourceRva)
      (invariantAfter : midpoint + 1 <= high /\ high <= records.length)
      (rankDecreases : high - (midpoint + 1) < high - low)
      (rest : ReflectedProgramLookupTrace records sourceRva
        (midpoint + 1) high resultIndex) :
      ReflectedProgramLookupTrace records sourceRva low high resultIndex
  | upper (low high midpoint resultIndex) (record : ProgramRecord)
      (invariantBefore : low <= high /\ high <= records.length)
      (notConverged : low < high)
      (midpointExact : midpoint = low + (high - low) / 2)
      (recordAt : listAt? records midpoint = some record)
      (recordNotLess : ¬ record.sourceRva < sourceRva)
      (invariantAfter : low <= midpoint /\ midpoint <= records.length)
      (rankDecreases : midpoint - low < high - low)
      (rest : ReflectedProgramLookupTrace records sourceRva
        low midpoint resultIndex) :
      ReflectedProgramLookupTrace records sourceRva low high resultIndex

/-- The reflected loop is total for every finite record list.  Its trace is
constructed by well-founded recursion on the machine rank, not supplied as a
summary field. -/
noncomputable def reflectedProgramLookupTrace (records : List ProgramRecord)
    (sourceRva low high : Nat)
    (invariant : low <= high /\ high <= records.length) :
    { resultIndex //
      ReflectedProgramLookupTrace records sourceRva low high resultIndex } := by
  by_cases converged : low = high
  · subst high
    exact ⟨low, .done low ⟨Nat.le_refl _, invariant.2⟩⟩
  · have notConverged : low < high := Nat.lt_of_le_of_ne invariant.1 converged
    let midpoint := low + (high - low) / 2
    have lowLeMidpoint : low <= midpoint := by
      simp only [midpoint]
      omega
    have midpointLtHigh : midpoint < high := by
      simp only [midpoint]
      omega
    have midpointInside : midpoint < records.length :=
      Nat.lt_of_lt_of_le midpointLtHigh invariant.2
    let recordWitness :=
      listAt?_witness_of_lt_length records midpoint midpointInside
    let record := recordWitness.1
    have recordAt : listAt? records midpoint = some record := recordWitness.2
    by_cases recordLess : record.sourceRva < sourceRva
    · have invariantAfter : midpoint + 1 <= high /\
          high <= records.length := ⟨midpointLtHigh, invariant.2⟩
      let restWitness := reflectedProgramLookupTrace records sourceRva
        (midpoint + 1) high invariantAfter
      let resultIndex := restWitness.1
      have rest : ReflectedProgramLookupTrace records sourceRva
          (midpoint + 1) high resultIndex := restWitness.2
      exact ⟨resultIndex, .lower low high midpoint resultIndex record invariant
        notConverged rfl recordAt recordLess invariantAfter (by omega) rest⟩
    · have invariantAfter : low <= midpoint /\ midpoint <= records.length :=
        ⟨lowLeMidpoint, Nat.le_trans (Nat.le_of_lt midpointLtHigh) invariant.2⟩
      let restWitness := reflectedProgramLookupTrace records sourceRva low
        midpoint invariantAfter
      let resultIndex := restWitness.1
      have rest : ReflectedProgramLookupTrace records sourceRva low midpoint
          resultIndex := restWitness.2
      exact ⟨resultIndex, .upper low high midpoint resultIndex record invariant
        notConverged rfl recordAt recordLess invariantAfter (by omega) rest⟩
termination_by high - low
decreasing_by all_goals omega

theorem reflectedProgramLookupTrace_exists (records : List ProgramRecord)
    (sourceRva low high : Nat)
    (invariant : low <= high /\ high <= records.length) :
    exists resultIndex,
      ReflectedProgramLookupTrace records sourceRva low high resultIndex :=
  let witness := reflectedProgramLookupTrace records sourceRva low high invariant
  ⟨witness.1, witness.2⟩

/-- Non-vacuous concrete entry premises for the reflected cdecl template.
They describe only initial registers and loaded memory, never a native path or
final state. -/
structure ProgramLookupLoadedEntry
    (pe : PE32) (parameters : ProgramLookupTemplateParameters)
    (records : List ProgramRecord) (transferCount sourceRva : Nat)
    (before : MachineState) where
  sourceFits : sourceRva < 2 ^ 32
  transferCountExact : transferCount = records.length
  stackHasFrame : 20 <= before.registers.esp.toNat
  returnAddress : Word
  returnAddressLoaded :
    Memory.read32 before.memory before.registers.esp = returnAddress
  sourceArgumentLoaded :
    Memory.read32 before.memory
      (before.registers.esp + BitVec.ofNat 32 4) =
        BitVec.ofNat 32 sourceRva
  countLoaded :
    Memory.read32 before.memory
      (BitVec.ofNat 32 (pe.imageBase + parameters.countRva)) =
        BitVec.ofNat 32 transferCount
  tableLoaded : forall index record,
    listAt? records index = some record ->
      Memory.read32 before.memory
        (programLookupTableAddress pe parameters.tableRva index) =
          BitVec.ofNat 32 record.sourceRva
  frameDisjointFromTable : forall frameOffset tableIndex,
    frameOffset < 20 -> tableIndex < transferCount ->
      programLookupFrameByte before.registers.esp frameOffset !=
        programLookupTableAddress pe parameters.tableRva tableIndex

def programLookupTemplateReturnedState (pe : PE32) (tableRva : Nat)
    (records : List ProgramRecord) (sourceRva : Nat)
    (before : MachineState) : MachineState :=
  { before with
    registers :=
      ((before.registers.set .eax
          (programLookupReturnWord pe tableRva records sourceRva)).set
        .edx (BitVec.ofNat 32 0)).set .esp
          (before.registers.esp + BitVec.ofNat 32 4)
    memory := programLookupTemplateFrameMemory before.registers.esp
      before.memory }

/-- Denotation of the reflected finite template.  This relation is kept
distinct from `NativeDispatches`: the checker establishes exact code identity,
while the instruction-to-native bridge must separately prove both relations
coincide. -/
def ProgramLookupTemplateDispatches
    (pe : PE32) (records : List ProgramRecord) (transferCount : Nat)
    (certificate : ProgramLookupTemplateCertificate program pe imports function) :
    KernelDispatchRelation :=
  fun entryRva before after events =>
    entryRva = certificate.parameters.entryRva /\
      exists sourceRva,
        exists resultIndex,
        Nonempty (ProgramLookupLoadedEntry pe certificate.parameters records
          transferCount sourceRva before) /\
        ReflectedProgramLookupTrace records sourceRva 0 transferCount
          resultIndex /\
        after = programLookupTemplateReturnedState pe
          certificate.parameters.tableRva records sourceRva before /\
        events = []

/-- A concrete lookup entry retains the exact request relation that established
the loaded cdecl/table facts.  Response and scratch proofs consume this object,
so they cannot be asked to prove preservation for an unrelated state that only
happens to satisfy the smaller machine-template entry predicate. -/
structure ProgramLookupConcreteEntry
    (pe : PE32) (abi : KernelABIRelation)
    (records : List ProgramRecord) (transferCount sourceRva : Nat)
    (before : MachineState)
    (certificate : ProgramLookupTemplateCertificate program pe imports function)
    where
  requestRelated : abi.requestRelated (.programLookup records sourceRva) before
  loaded : ProgramLookupLoadedEntry pe certificate.parameters records
    transferCount sourceRva before

/-- Candidate ABI boundary.  `requestEntry` exposes the actual cdecl stack and
PE-backed table loads while retaining their originating request proof.
`responseExit` interprets the deterministic result for that same entry; no
field contains an execution or caller-supplied final state. -/
structure ProgramLookupConcreteABI
    (pe : PE32) (abi : KernelABIRelation)
    (records : List ProgramRecord) (transferCount : Nat)
    (certificate : ProgramLookupTemplateCertificate program pe imports function) :
    Prop where
  requestEntry : forall requestRecords sourceRva before,
    abi.requestRelated (.programLookup requestRecords sourceRva) before ->
      requestRecords = records /\
      Nonempty (ProgramLookupConcreteEntry pe abi records transferCount sourceRva
        before certificate)
  responseExit : forall sourceRva before,
    ProgramLookupConcreteEntry pe abi records transferCount sourceRva before
      certificate ->
    abi.responseRelated (.programLookup records sourceRva)
      (.programLookup
        (StageA.Relational.InterpreterKernel.lookupProgramRecord
          records sourceRva))
      (programLookupTemplateReturnedState pe certificate.parameters.tableRva
        records sourceRva before) []
  scratchContainsFrame : forall sourceRva before address,
    ProgramLookupConcreteEntry pe abi records transferCount sourceRva before
      certificate ->
    programLookupFrameFootprint before.registers.esp address ->
      abi.scratchFootprint (.programLookup records sourceRva) address

/-- Derived invocation summary.  Unlike the old API, it contains no supplied
simulation field: its dispatch fact is constructed from checked template data
and a loaded entry state. -/
structure ProgramLookupExecutionSummary
    (pe : PE32) (abi : KernelABIRelation) (records : List ProgramRecord)
    (transferCount sourceRva : Nat) (before : MachineState)
    (certificate : ProgramLookupTemplateCertificate program pe imports function)
    (concreteABI : ProgramLookupConcreteABI pe abi records transferCount
      certificate) where
  templateChecked : programLookupTemplateChecked program pe imports function
    certificate.parameters = true
  exactReflection : reflectProgramLookupTemplate? pe function =
    some certificate.reflection
  instructionExecution : forall block, block ∈ function.blocks ->
    forall undefinedSlot input,
      runKernelBlockConcrete pe imports undefinedSlot input block.instructions =
        runKernelBlockSemantic pe imports undefinedSlot input block.instructions
  recordsSorted : sourceRvasStrictlySorted records
  entry : ProgramLookupConcreteEntry pe abi records transferCount sourceRva before
    certificate
  resultIndex : Nat
  binarySearchTrace : ReflectedProgramLookupTrace records sourceRva 0
    transferCount resultIndex
  after : MachineState := programLookupTemplateReturnedState pe
    certificate.parameters.tableRva records sourceRva before
  result : Option ProgramRecord :=
    StageA.Relational.InterpreterKernel.lookupProgramRecord records sourceRva
  templateExecution : ProgramLookupTemplateDispatches pe records transferCount
    certificate certificate.parameters.entryRva before after []
  exactLookupResult : result =
    StageA.Relational.InterpreterKernel.lookupProgramRecord records sourceRva
  indexedLookupExact :
    (lookupProgramRecordWithIndex? records sourceRva).map Prod.snd = result
  abiReturnRegister : after.registers.get .eax =
    programLookupReturnWord pe certificate.parameters.tableRva records sourceRva
  abiResponse : abi.responseRelated (.programLookup records sourceRva)
    (.programLookup result) after []
  memoryFrame : MemoryAgreesOutside
    (abi.scratchFootprint (.programLookup records sourceRva))
    after.memory before.memory

noncomputable def ProgramLookupTemplateCertificate.executionSummary
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {abi : KernelABIRelation}
    {records : List ProgramRecord} {transferCount sourceRva : Nat}
    {before : MachineState}
    (certificate : ProgramLookupTemplateCertificate program pe imports function)
    (concreteABI : ProgramLookupConcreteABI pe abi records transferCount certificate)
    (entry : ProgramLookupConcreteEntry pe abi records transferCount sourceRva
      before certificate)
    (instructionExecution : forall block, block ∈ function.blocks ->
      forall undefinedSlot input,
        runKernelBlockConcrete pe imports undefinedSlot input block.instructions =
          runKernelBlockSemantic pe imports undefinedSlot input
            block.instructions)
    (recordsSorted : sourceRvasStrictlySorted records) :
    ProgramLookupExecutionSummary pe abi records transferCount sourceRva before
      certificate concreteABI := by
  let after := programLookupTemplateReturnedState pe
    certificate.parameters.tableRva records sourceRva before
  let traceWitness := reflectedProgramLookupTrace records sourceRva 0
    records.length ⟨Nat.zero_le _, Nat.le_refl _⟩
  let resultIndex := traceWitness.1
  have binarySearchTrace : ReflectedProgramLookupTrace records sourceRva 0
      records.length resultIndex := traceWitness.2
  have binarySearchTrace' : ReflectedProgramLookupTrace records sourceRva 0
      transferCount resultIndex := by
    simpa [entry.loaded.transferCountExact] using binarySearchTrace
  refine {
    templateChecked := certificate.checked
    exactReflection := certificate.reflected
    instructionExecution
    recordsSorted
    entry
    resultIndex
    binarySearchTrace := binarySearchTrace'
    after
    templateExecution := ?_
    exactLookupResult := rfl
    indexedLookupExact := lookupProgramRecordWithIndex?_recordExact records sourceRva
    abiReturnRegister := ?_
    abiResponse := ?_
    memoryFrame := ?_
  }
  · exact ⟨rfl, sourceRva, resultIndex, ⟨entry.loaded⟩,
      binarySearchTrace', rfl, rfl⟩
  · simp [after, programLookupTemplateReturnedState, Registers.get,
      Registers.set]
  · simpa [after] using concreteABI.responseExit sourceRva before entry
  · intro address outsideScratch
    apply programLookupTemplateFrameMemory_agreesOutside
      before.registers.esp before.memory address
    intro inFrame
    exact outsideScratch
      (concreteABI.scratchContainsFrame sourceRva before address entry inFrame)

/-- Soundness boundary for one reflected invocation.  Its premises are the
checked template, concrete loaded entry, sorted table, ABI interpretation, and
instruction-granular exact execution theorem; no final state or simulation is
accepted from the caller. -/
theorem ProgramLookupTemplateCertificate.sound
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {abi : KernelABIRelation}
    {records : List ProgramRecord} {transferCount sourceRva : Nat}
    {before : MachineState}
    (certificate : ProgramLookupTemplateCertificate program pe imports function)
    (concreteABI : ProgramLookupConcreteABI pe abi records transferCount certificate)
    (entry : ProgramLookupConcreteEntry pe abi records transferCount sourceRva
      before certificate)
    (instructionExecution : forall block, block ∈ function.blocks ->
      forall undefinedSlot input,
        runKernelBlockConcrete pe imports undefinedSlot input block.instructions =
          runKernelBlockSemantic pe imports undefinedSlot input block.instructions)
    (recordsSorted : sourceRvasStrictlySorted records) :
    Nonempty (ProgramLookupExecutionSummary pe abi records transferCount
      sourceRva before certificate concreteABI) :=
  ⟨certificate.executionSummary concreteABI entry instructionExecution
    recordsSorted⟩

/-- Checked generic summary.  There is deliberately no `simulate` field. -/
structure KernelFunctionSummary
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (abi : KernelABIRelation) (relocations : List BaseRelocation)
    (tableRva countRva : Nat) (semanticRecords : List ProgramRecord)
    (function : KernelFunction) where
  candidateParsed : parsePE32Tree pe.bytes = some pe
  templateCertificate :
    ProgramLookupTemplateCertificate program pe imports function
  tableParameterExact : templateCertificate.parameters.tableRva = tableRva
  countParameterExact : templateCertificate.parameters.countRva = countRva
  instructionDecodes : ExactDecodeInventory pe function.instructions
  dataCertificate : ProgramTableCertificate pe imports relocations
    tableRva countRva semanticRecords
  transferCountExact : dataCertificate.transferCount = semanticRecords.length
  sourceRvasSorted : sourceRvasStrictlySorted semanticRecords
  entryRvaExact : program.functionEntry? .programLookup =
    some templateCertificate.parameters.entryRva
  concreteABI : ProgramLookupConcreteABI pe abi semanticRecords
    dataCertificate.transferCount templateCertificate

/-- Sequential execution of every submitted ordinary block is assembled from
`executeInstruction_composes`; no fused block summary is trusted here. -/
theorem KernelFunctionSummary.blockExecutionComposes
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {abi : KernelABIRelation}
    {relocations : List BaseRelocation} {tableRva countRva : Nat}
    {semanticRecords : List ProgramRecord} {function : KernelFunction}
    (summary : KernelFunctionSummary program pe imports abi relocations tableRva
      countRva semanticRecords function)
    (block : KernelBlock) (member : block ∈ function.blocks) :
    forall undefinedSlot input,
      runKernelBlockConcrete pe imports undefinedSlot input block.instructions =
        runKernelBlockSemantic pe imports undefinedSlot input block.instructions := by
  apply runKernelBlockConcrete_composes
  intro instruction instructionMember
  apply summary.instructionDecodes instruction
  simp only [KernelFunction.instructions, List.mem_flatMap]
  exact ⟨block, member, instructionMember⟩

/-- Construct the complete operation simulation for the reflected template.
No caller supplies a final invocation or native execution witness. -/
theorem KernelFunctionSummary.programLookupTemplateSimulate
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {abi : KernelABIRelation}
    {relocations : List BaseRelocation} {tableRva countRva : Nat}
    {semanticRecords : List ProgramRecord} {function : KernelFunction}
    (summary : KernelFunctionSummary program pe imports abi relocations tableRva
      countRva semanticRecords function) :
    forall request before,
      request.operation = .programLookup -> abi.requestRelated request before ->
      forall response, AbstractKernelTransition request response ->
        exists entryRva after nativeEvents,
          program.functionEntry? KernelOperation.programLookup.role = some entryRva /\
          ProgramLookupTemplateDispatches pe semanticRecords
            summary.dataCertificate.transferCount summary.templateCertificate
            entryRva before after nativeEvents /\
          abi.responseRelated request response after nativeEvents /\
          MemoryAgreesOutside (abi.scratchFootprint request)
            after.memory before.memory := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      obtain ⟨recordsExact, ⟨entry⟩⟩ :=
        summary.concreteABI.requestEntry records sourceRva before requestRelated
      subst records
      cases transition
      have execution := summary.templateCertificate.executionSummary
        summary.concreteABI entry summary.blockExecutionComposes
        summary.sourceRvasSorted
      refine ⟨summary.templateCertificate.parameters.entryRva, execution.after,
        [], summary.entryRvaExact, execution.templateExecution, ?_,
        execution.memoryFrame⟩
      simpa [execution.exactLookupResult] using execution.abiResponse
  | interpreterStep records requestEnvironment sourceRva state =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records requestEnvironment resolveCodeTarget sourceRva state =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records requestEnvironment resolveCodeTarget event state =>
      simp [AbstractKernelRequest.operation] at operationMatches

/-- Real `.programLookup` theorem for the reflected template dispatch.  The
separate native bridge is intentionally not claimed by this theorem. -/
theorem KernelFunctionSummary.programLookupRefinesUsingTemplate
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {abi : KernelABIRelation}
    {relocations : List BaseRelocation} {tableRva countRva : Nat}
    {semanticRecords : List ProgramRecord} {function : KernelFunction}
    (summary : KernelFunctionSummary program pe imports abi relocations tableRva
      countRva semanticRecords function) :
    KernelOperationRefinesUsing program abi
      (ProgramLookupTemplateDispatches pe semanticRecords
        summary.dataCertificate.transferCount summary.templateCertificate)
      .programLookup :=
  summary.programLookupTemplateSimulate

#print axioms BinarySearchRank.eq_high_sub_low
#print axioms ExactKernelCFGPath.thenExecution
#print axioms ProgramLookupLoopTrace.toExactCFGPath
#print axioms reflectedProgramLookupTrace_exists
#print axioms ProgramLookupTemplateCertificate.executionSummary
#print axioms ProgramLookupTemplateCertificate.sound
#print axioms KernelFunctionSummary.blockExecutionComposes
#print axioms KernelFunctionSummary.programLookupTemplateSimulate
#print axioms KernelFunctionSummary.programLookupRefinesUsingTemplate

end StageA.Relational.InterpreterKernelSummary
