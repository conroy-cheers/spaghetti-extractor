import StageA.Relational

namespace StageA.Relational.Engine

open StageA.Formal

/-- Architectural values represented in an engine-state allocation.  Candidate
CPU registers are deliberately absent: an engine may use them as scratch. -/
inductive EngineField where
  | register (register : Reg)
  | eflags
  | flag (bit : Nat)
  | fsBase
  | x87Stack (index : Nat)
  | x87Empty (index : Nat)
  | x87Tag (index : Nat)
  | x87Control
  | x87Status
  | x87PendingException
  | x87LastOpcode
  | x87InstructionPointer
  | x87CodeSelector
  | x87DataPointer
  | x87DataSelector
  | originalRva
deriving Repr, DecidableEq

def EngineField.byteWidth : EngineField -> Nat
  | .register _ | .eflags | .flag _ | .fsBase | .x87Empty _ | .originalRva => 4
  | .x87Stack _ => 10
  | .x87Tag _ | .x87PendingException => 1
  | .x87Control | .x87Status | .x87LastOpcode |
      .x87CodeSelector | .x87DataSelector => 2
  | .x87InstructionPointer | .x87DataPointer => 4

structure EngineFieldLayout where
  field : EngineField
  offset : Nat
  alignment : Nat
deriving Repr, DecidableEq

def EngineFieldLayout.stop (entry : EngineFieldLayout) : Nat :=
  entry.offset + entry.field.byteWidth

def EngineFieldLayout.disjoint (left right : EngineFieldLayout) : Prop :=
  left.stop <= right.offset ∨ right.stop <= left.offset

def EngineFieldLayout.disjointChecked (left right : EngineFieldLayout) : Bool :=
  left.stop <= right.offset || right.stop <= left.offset

def allRegisters : List Reg :=
  [.eax, .ebx, .ecx, .edx, .esi, .edi, .ebp, .esp]

/-- A layout is data only.  Its checker does not establish any program-level
refinement claim and is not wired into Stage A acceptance. -/
structure EngineLayout where
  stateSize : Nat
  x87StackSlots : Nat
  fields : List EngineFieldLayout
deriving Repr, DecidableEq

def EngineFieldLayout.checkedFor (layout : EngineLayout)
    (entry : EngineFieldLayout) : Bool :=
  entry.alignment > 0 &&
    entry.offset % entry.alignment == 0 &&
    entry.field.byteWidth % entry.alignment == 0 &&
    entry.stop <= layout.stateSize &&
    match entry.field with
    | .flag bit => bit < 32
    | .x87Stack index | .x87Empty index | .x87Tag index =>
        index < layout.x87StackSlots
    | _ => true

def EngineFieldLayout.ValidFor (layout : EngineLayout)
    (entry : EngineFieldLayout) : Prop :=
  0 < entry.alignment ∧
    entry.offset % entry.alignment = 0 ∧
    entry.field.byteWidth % entry.alignment = 0 ∧
    entry.stop <= layout.stateSize ∧
    match entry.field with
    | .flag bit => bit < 32
    | .x87Stack index | .x87Empty index | .x87Tag index =>
        index < layout.x87StackSlots
    | _ => True

theorem EngineFieldLayout.checkedFor_eq_true_iff
    (layout : EngineLayout) (entry : EngineFieldLayout) :
    entry.checkedFor layout = true ↔ entry.ValidFor layout := by
  rcases entry with ⟨field, offset, alignment⟩
  cases field <;>
    simp [EngineFieldLayout.checkedFor, EngineFieldLayout.ValidFor, and_assoc]

def EngineLayout.requiredFields (layout : EngineLayout) : List EngineField :=
  allRegisters.map EngineField.register ++
    [.eflags, .fsBase, .x87Control, .x87Status, .x87PendingException,
      .x87LastOpcode, .x87InstructionPointer, .x87CodeSelector,
      .x87DataPointer, .x87DataSelector, .originalRva] ++
    (List.range layout.x87StackSlots).map EngineField.x87Stack ++
    (List.range layout.x87StackSlots).map EngineField.x87Empty ++
    (List.range layout.x87StackSlots).map EngineField.x87Tag

def fieldLayoutsDisjointChecked : List EngineFieldLayout -> Bool
  | [] => true
  | entry :: tail =>
      tail.all (EngineFieldLayout.disjointChecked entry) &&
        fieldLayoutsDisjointChecked tail

theorem EngineFieldLayout.disjointChecked_eq_true_iff
    (left right : EngineFieldLayout) :
    left.disjointChecked right = true ↔ left.disjoint right := by
  simp [EngineFieldLayout.disjointChecked, EngineFieldLayout.disjoint]

theorem fieldLayoutsDisjointChecked_eq_true_iff
    (fields : List EngineFieldLayout) :
    fieldLayoutsDisjointChecked fields = true ↔
      fields.Pairwise EngineFieldLayout.disjoint := by
  induction fields with
  | nil => simp [fieldLayoutsDisjointChecked]
  | cons entry tail induction =>
      simp [fieldLayoutsDisjointChecked, induction,
        EngineFieldLayout.disjointChecked_eq_true_iff]

/-- Executable structural checker for exact field-name uniqueness, in-bounds
non-overlapping storage, and declared alignment. -/
def EngineLayout.checked (layout : EngineLayout) : Bool :=
  layout.stateSize > 0 &&
    layout.stateSize <= 2 ^ 32 &&
    decide (layout.fields.map (fun entry => entry.field)).Nodup &&
    layout.fields.all (EngineFieldLayout.checkedFor layout) &&
    fieldLayoutsDisjointChecked layout.fields &&
    layout.requiredFields.all (fun field =>
      layout.fields.any (fun entry => entry.field == field))

/-- Structural proposition certified by `EngineLayout.checked`. -/
def EngineLayout.Valid (layout : EngineLayout) : Prop :=
  0 < layout.stateSize ∧
    layout.stateSize <= 2 ^ 32 ∧
    (layout.fields.map (fun entry => entry.field)).Nodup ∧
    (∀ entry ∈ layout.fields, entry.ValidFor layout) ∧
    layout.fields.Pairwise EngineFieldLayout.disjoint ∧
    (∀ field ∈ layout.requiredFields,
      field ∈ layout.fields.map (fun entry => entry.field))

theorem EngineLayout.checked_iff_valid (layout : EngineLayout) :
    layout.checked = true ↔ layout.Valid := by
  simp [EngineLayout.checked, EngineLayout.Valid,
    EngineFieldLayout.checkedFor_eq_true_iff,
    fieldLayoutsDisjointChecked_eq_true_iff, and_assoc]

theorem EngineLayout.valid_of_checked (layout : EngineLayout)
    (checked : layout.checked = true) : layout.Valid :=
  (layout.checked_iff_valid).mp checked

theorem EngineLayout.checked_of_valid (layout : EngineLayout)
    (valid : layout.Valid) : layout.checked = true :=
  (layout.checked_iff_valid).mpr valid

def EngineFieldLayout.address (engineBase : Word)
    (entry : EngineFieldLayout) : Word :=
  engineBase + BitVec.ofNat 32 entry.offset

/-- Read an exact byte range from candidate memory.  Keeping the generic field
reader byte-oriented supports 16-, 32-, and 80-bit architectural fields without
padding or host-endianness assumptions. -/
def readBytes (memory : Memory) (address : Word) (count : Nat) : List (BitVec 8) :=
  (List.range count).map fun offset =>
    memory (address + BitVec.ofNat 32 offset)

def encodeLittleEndian (count value : Nat) : List (BitVec 8) :=
  (List.range count).map fun offset =>
    BitVec.ofNat 8 (value / 2 ^ (offset * 8))

/-- The candidate byte address corresponding to an original byte when that
byte belongs to a certified represented range.  Keeping the map partial is
essential: engine stacks, dispatch tables, and other candidate-only storage
must not become observable merely because x86 memory is modeled as a total
function. -/
abbrev MemoryAddressMap := Word -> Option Word

def MemoryAddressMap.InjectiveOnMapped (memoryAddress : MemoryAddressMap) : Prop :=
  ∀ originalLeft originalRight candidateAddress,
    memoryAddress originalLeft = some candidateAddress ->
      memoryAddress originalRight = some candidateAddress ->
      originalLeft = originalRight

def MemoryAddressMap.AvoidsEngineFields (layout : EngineLayout)
    (engineBase : Word) (memoryAddress : MemoryAddressMap) : Prop :=
  ∀ originalAddress candidateAddress,
    memoryAddress originalAddress = some candidateAddress ->
      ∀ entry ∈ layout.fields, ∀ byteOffset,
        byteOffset < entry.field.byteWidth ->
          candidateAddress !=
            entry.address engineBase + BitVec.ofNat 32 byteOffset

def MemoryAddressMap.Valid (layout : EngineLayout) (engineBase : Word)
    (memoryAddress : MemoryAddressMap) : Prop :=
  memoryAddress.InjectiveOnMapped ∧
    memoryAddress.AvoidsEngineFields layout engineBase

/-- A semantic engine representation.  Code, data, and ordinary memory maps
are separate because a relocated candidate may use different witnesses for
each address class.  The x87 semantics remains a qualified Lean object and is
never assigned an engine-memory field. -/
structure EngineRep where
  layout : EngineLayout
  engineBase : Word
  memoryAddress : MemoryAddressMap
  codeAddress : MemoryAddressMap
  dataAddress : MemoryAddressMap
  x87Semantics : StageA.X87.Semantics

def EngineRep.Valid (rep : EngineRep) : Prop :=
  rep.layout.Valid ∧
    rep.layout.x87StackSlots = 8 ∧
    rep.memoryAddress.Valid rep.layout rep.engineBase ∧
    rep.codeAddress.InjectiveOnMapped ∧
    rep.dataAddress.InjectiveOnMapped

def EngineRep.x87AddressRelation (rep : EngineRep) :
    StageA.Relational.X87.AddressRelation := {
  code := fun original candidate => rep.codeAddress original = some candidate
  data := fun original candidate => rep.dataAddress original = some candidate
}

def boolValue : Bool -> Nat
  | false => 0
  | true => 1

/-- Canonical persistent payload for one logical x87 slot.  Empty slots have
zero payload bytes; occupancy and the authoritative tag remain separate. -/
def x87SlotValue : StageA.X87.Slot -> StageA.X87.Word
  | .empty => BitVec.ofNat 80 0
  | .occupied _ value => value

def x87SlotEmpty : StageA.X87.Slot -> Nat
  | .empty => 1
  | .occupied _ _ => 0

/-- Intel tag encoding, with `3` also carrying empty occupancy. -/
def x87SlotTag : StageA.X87.Slot -> Nat
  | .empty => 3
  | .occupied .valid _ => 0
  | .occupied .zero _ => 1
  | .occupied .special _ => 2

/-- Exact bytes expected in an engine allocation.  Relocated x87 metadata
pointers are available only when their partial code/data maps provide a
witness. -/
def EngineRep.fieldBytes (rep : EngineRep) (original : MachineState)
    (originalRva : Nat) : EngineField -> Option (List (BitVec 8))
  | field@(.register register) => some <|
      encodeLittleEndian field.byteWidth (original.registers.get register).toNat
  | field@.eflags => some <|
      encodeLittleEndian field.byteWidth original.eflags.toNat
  | field@(.flag bit) => some <| encodeLittleEndian field.byteWidth
      (original.eflags.extractLsb' bit 1).toNat
  | field@.fsBase => some <|
      encodeLittleEndian field.byteWidth original.fsBase.toNat
  | field@(.x87Stack index) => some <| encodeLittleEndian field.byteWidth
      (x87SlotValue (original.x87Physical.logicalSlot index)).toNat
  | field@(.x87Empty index) => some <| encodeLittleEndian field.byteWidth
      (x87SlotEmpty (original.x87Physical.logicalSlot index))
  | field@(.x87Tag index) => some <| encodeLittleEndian field.byteWidth
      (x87SlotTag (original.x87Physical.logicalSlot index))
  | field@.x87Control => some <|
      encodeLittleEndian field.byteWidth original.x87Physical.control.toNat
  | field@.x87Status => some <|
      encodeLittleEndian field.byteWidth original.x87Physical.status.toNat
  | field@.x87PendingException => some <| encodeLittleEndian field.byteWidth
      (boolValue original.x87Physical.pendingException)
  | field@.x87LastOpcode => some <|
      encodeLittleEndian field.byteWidth original.x87Physical.lastOpcode.toNat
  | field@.x87InstructionPointer =>
      (rep.codeAddress original.x87Physical.instructionPointer).map fun address =>
        encodeLittleEndian field.byteWidth address.toNat
  | field@.x87CodeSelector => some <|
      encodeLittleEndian field.byteWidth original.x87Physical.codeSelector.toNat
  | field@.x87DataPointer =>
      (rep.dataAddress original.x87Physical.dataPointer).map fun address =>
        encodeLittleEndian field.byteWidth address.toNat
  | field@.x87DataSelector => some <|
      encodeLittleEndian field.byteWidth original.x87Physical.dataSelector.toNat
  | field@.originalRva => some <| encodeLittleEndian field.byteWidth originalRva

def EngineFieldHolds (rep : EngineRep) (original : MachineState)
    (originalRva : Nat) (candidateMemory : Memory)
    (entry : EngineFieldLayout) : Prop :=
  some (readBytes candidateMemory (entry.address rep.engineBase)
    entry.field.byteWidth) = rep.fieldBytes original originalRva entry.field

/-- Candidate addresses observed by the representation.  Everything outside
this set is candidate scratch memory. -/
def CandidateAddressObserved (rep : EngineRep) (address : Word) : Prop :=
  (∃ entry ∈ rep.layout.fields, ∃ byteOffset,
      byteOffset < entry.field.byteWidth ∧
        address = entry.address rep.engineBase + BitVec.ofNat 32 byteOffset) ∨
    ∃ originalAddress, rep.memoryAddress originalAddress = some address

def CandidateMemoryAgreesOnRepresentation (rep : EngineRep)
    (after before : Memory) : Prop :=
  ∀ address, CandidateAddressObserved rep address →
    after address = before address

/-- Representation of one original-machine cutpoint by an engine allocation in
candidate memory.  `CandidateControl` and its relation remain abstract so the
kernel does not assume a dispatcher shape, candidate RVA, or host ABI. -/
structure StateRelated {CandidateControl : Type}
    (rep : EngineRep)
    (controlRelated : Nat -> CandidateControl -> Prop)
    (originalRva : Nat) (candidateControl : CandidateControl)
    (original candidate : MachineState) : Prop where
  repValid : rep.Valid
  fields : ∀ entry ∈ rep.layout.fields,
    EngineFieldHolds rep original originalRva candidate.memory entry
  memory : ∀ originalAddress candidateAddress,
    rep.memoryAddress originalAddress = some candidateAddress ->
      candidate.memory candidateAddress = original.memory originalAddress
  control : controlRelated originalRva candidateControl
  originalSemantics : original.x87Semantics = rep.x87Semantics
  candidateSemantics : candidate.x87Semantics = rep.x87Semantics

theorem StateRelated.read_mapped_field {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields) :
    some (readBytes candidate.memory (entry.address rep.engineBase)
      entry.field.byteWidth) =
        rep.fieldBytes original originalRva entry.field :=
  related.fields entry member

theorem StateRelated.read_register {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (register : Reg) (mapped : entry.field = .register register) :
    readBytes candidate.memory (entry.address rep.engineBase) 4 =
      encodeLittleEndian 4 (original.registers.get register).toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_flags {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .eflags) :
    readBytes candidate.memory (entry.address rep.engineBase) 4 =
      encodeLittleEndian 4 original.eflags.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_flag {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (bit : Nat) (mapped : entry.field = .flag bit) :
    readBytes candidate.memory (entry.address rep.engineBase) 4 =
      encodeLittleEndian 4 (original.eflags.extractLsb' bit 1).toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_fs_base {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .fsBase) :
    readBytes candidate.memory (entry.address rep.engineBase) 4 =
      encodeLittleEndian 4 original.fsBase.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_stack {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (index : Nat) (mapped : entry.field = .x87Stack index) :
    readBytes candidate.memory (entry.address rep.engineBase) 10 =
      encodeLittleEndian 10
        (x87SlotValue (original.x87Physical.logicalSlot index)).toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_stack_occupied {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (index : Nat) (mapped : entry.field = .x87Stack index)
    (tag : StageA.X87.Tag) (value : StageA.X87.Word)
    (occupied : original.x87Physical.logicalSlot index = .occupied tag value) :
    readBytes candidate.memory (entry.address rep.engineBase) 10 =
      encodeLittleEndian 10 value.toNat := by
  rw [related.read_x87_stack entry member index mapped, occupied]
  rfl

theorem StateRelated.read_x87_empty {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (index : Nat) (mapped : entry.field = .x87Empty index) :
    readBytes candidate.memory (entry.address rep.engineBase) 4 =
      encodeLittleEndian 4
        (x87SlotEmpty (original.x87Physical.logicalSlot index)) := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_tag {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (index : Nat) (mapped : entry.field = .x87Tag index) :
    readBytes candidate.memory (entry.address rep.engineBase) 1 =
      encodeLittleEndian 1
        (x87SlotTag (original.x87Physical.logicalSlot index)) := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_control {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87Control) :
    readBytes candidate.memory (entry.address rep.engineBase) 2 =
      encodeLittleEndian 2 original.x87Physical.control.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_status {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87Status) :
    readBytes candidate.memory (entry.address rep.engineBase) 2 =
      encodeLittleEndian 2 original.x87Physical.status.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_pending_exception {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87PendingException) :
    readBytes candidate.memory (entry.address rep.engineBase) 1 =
      encodeLittleEndian 1 (boolValue original.x87Physical.pendingException) := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_last_opcode {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87LastOpcode) :
    readBytes candidate.memory (entry.address rep.engineBase) 2 =
      encodeLittleEndian 2 original.x87Physical.lastOpcode.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_instruction_pointer {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87InstructionPointer) :
    ∃ candidateAddress,
      rep.codeAddress original.x87Physical.instructionPointer =
        some candidateAddress ∧
      readBytes candidate.memory (entry.address rep.engineBase) 4 =
        encodeLittleEndian 4 candidateAddress.toNat := by
  have holds := related.fields entry member
  cases addressFound : rep.codeAddress original.x87Physical.instructionPointer with
  | none => simp [EngineFieldHolds, mapped, EngineRep.fieldBytes, addressFound] at holds
  | some candidateAddress =>
      refine ⟨candidateAddress, rfl, ?_⟩
      simpa [EngineFieldHolds, mapped, EngineField.byteWidth,
        EngineRep.fieldBytes, addressFound] using holds

theorem StateRelated.read_x87_code_selector {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87CodeSelector) :
    readBytes candidate.memory (entry.address rep.engineBase) 2 =
      encodeLittleEndian 2 original.x87Physical.codeSelector.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_x87_data_pointer {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87DataPointer) :
    ∃ candidateAddress,
      rep.dataAddress original.x87Physical.dataPointer = some candidateAddress ∧
      readBytes candidate.memory (entry.address rep.engineBase) 4 =
        encodeLittleEndian 4 candidateAddress.toNat := by
  have holds := related.fields entry member
  cases addressFound : rep.dataAddress original.x87Physical.dataPointer with
  | none => simp [EngineFieldHolds, mapped, EngineRep.fieldBytes, addressFound] at holds
  | some candidateAddress =>
      refine ⟨candidateAddress, rfl, ?_⟩
      simpa [EngineFieldHolds, mapped, EngineField.byteWidth,
        EngineRep.fieldBytes, addressFound] using holds

theorem StateRelated.read_x87_data_selector {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .x87DataSelector) :
    readBytes candidate.memory (entry.address rep.engineBase) 2 =
      encodeLittleEndian 2 original.x87Physical.dataSelector.toNat := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.read_original_rva {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields)
    (mapped : entry.field = .originalRva) :
    readBytes candidate.memory (entry.address rep.engineBase) 4 =
      encodeLittleEndian 4 originalRva := by
  simpa [EngineFieldHolds, mapped, EngineField.byteWidth, EngineRep.fieldBytes]
    using related.fields entry member

theorem StateRelated.shared_x87_semantics {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    original.x87Semantics = candidate.x87Semantics :=
  related.originalSemantics.trans related.candidateSemantics.symm

theorem StateRelated.x87_semantics_qualified {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (_related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    rep.x87Semantics.Complies :=
  rep.x87Semantics.complies

theorem StateRelated.read_mapped_memory {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (originalAddress candidateAddress : Word)
    (mapped : rep.memoryAddress originalAddress = some candidateAddress) :
    candidate.memory candidateAddress = original.memory originalAddress :=
  related.memory originalAddress candidateAddress mapped

theorem readBytes_eq_of_candidate_memory_agreement
    {rep : EngineRep} {after before : Memory}
    (agrees : CandidateMemoryAgreesOnRepresentation rep after before)
    (entry : EngineFieldLayout) (member : entry ∈ rep.layout.fields) :
    readBytes after (entry.address rep.engineBase) entry.field.byteWidth =
      readBytes before (entry.address rep.engineBase) entry.field.byteWidth := by
  unfold readBytes
  apply List.map_congr_left
  intro offset offsetMember
  apply agrees
  exact Or.inl ⟨entry, member, offset, List.mem_range.mp offsetMember, rfl⟩

/-- Changes to unobserved candidate scratch memory preserve every represented
field, every mapped original byte, and the abstract control relation. -/
theorem StateRelated.preserve_candidate_scratch {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidateBefore candidateAfter : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidateBefore)
    (agrees : CandidateMemoryAgreesOnRepresentation rep
      candidateAfter.memory candidateBefore.memory)
    (semantics : candidateAfter.x87Semantics = candidateBefore.x87Semantics) :
    StateRelated rep controlRelated
      originalRva candidateControl original candidateAfter := by
  refine ⟨related.repValid, ?_, ?_, related.control,
    related.originalSemantics, ?_⟩
  · intro entry member
    unfold EngineFieldHolds
    rw [readBytes_eq_of_candidate_memory_agreement agrees entry member]
    exact related.fields entry member
  · intro originalAddress candidateAddress mapped
    rw [agrees candidateAddress (Or.inr ⟨originalAddress, mapped⟩)]
    exact related.memory originalAddress candidateAddress mapped
  · exact semantics.trans related.candidateSemantics

theorem candidate_memory_agrees_write8_of_unobserved
    {rep : EngineRep} (before : Memory)
    (scratchAddress : Word) (value : BitVec 8)
    (unobserved : ¬ CandidateAddressObserved rep scratchAddress) :
    CandidateMemoryAgreesOnRepresentation rep
      (Memory.write8 before scratchAddress value) before := by
  intro address observed
  have different : address ≠ scratchAddress := by
    intro equal
    apply unobserved
    rw [← equal]
    exact observed
  simp [Memory.write8, different]

theorem StateRelated.write_candidate_scratch_byte {CandidateControl : Type}
    {rep : EngineRep}
    {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidate : MachineState}
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (scratchAddress : Word) (value : BitVec 8)
    (unobserved : ¬ CandidateAddressObserved rep scratchAddress) :
    StateRelated rep controlRelated originalRva
      candidateControl original
      { candidate with memory := Memory.write8 candidate.memory scratchAddress value } :=
  related.preserve_candidate_scratch
    (candidate_memory_agrees_write8_of_unobserved candidate.memory
      scratchAddress value unobserved) rfl

structure OriginalMacroStepResult where
  state : MachineState
  currentRva : Nat

structure CandidateMacroStepResult (CandidateControl : Type) where
  state : MachineState
  control : CandidateControl

/-- A reusable result-relation interface.  The canonical constructor below
instantiates it with `StateRelated`; future engine semantics can use the same
macro-step simulation shape without changing this kernel. -/
structure MacroStepResultRelation (CandidateControl : Type) where
  relates : OriginalMacroStepResult -> CandidateMacroStepResult CandidateControl -> Prop

def representationResultRelation {CandidateControl : Type}
    (rep : EngineRep)
    (controlRelated : Nat -> CandidateControl -> Prop) :
    MacroStepResultRelation CandidateControl := {
  relates := fun original candidate =>
    StateRelated rep controlRelated
      original.currentRva candidate.control original.state candidate.state
}

structure MacroStepSemantics (CandidateControl : Type) where
  originalStep : OriginalMacroStepResult -> OriginalMacroStepResult -> Prop
  candidateStep : CandidateMacroStepResult CandidateControl ->
    CandidateMacroStepResult CandidateControl -> Prop

/-- Forward simulation obligation for one engine macro-step.  This proposition
is an interface only; no acceptance theorem consumes it yet. -/
def MacroStepSimulation {CandidateControl : Type}
    (semantics : MacroStepSemantics CandidateControl)
    (resultRelation : MacroStepResultRelation CandidateControl) : Prop :=
  ∀ originalBefore candidateBefore candidateAfter,
    resultRelation.relates originalBefore candidateBefore →
      semantics.candidateStep candidateBefore candidateAfter →
      ∃ originalAfter,
        semantics.originalStep originalBefore originalAfter ∧
          resultRelation.relates originalAfter candidateAfter

end StageA.Relational.Engine
