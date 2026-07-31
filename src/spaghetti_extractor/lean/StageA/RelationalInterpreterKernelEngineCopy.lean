import StageA.RelationalInterpreterKernelOperationEffectChecker

namespace StageA.Relational.InterpreterKernelEngineCopy

open StageA.Formal StageA.Relational
open StageA.Relational.Engine StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationEffectChecker
open StageA.Relational.InterpreterKernelOperationReplay

/-!
# Engine-state memory transport

These theorems separate operation control proofs from the byte-level engine
representation. They are generic over engine layouts and concrete addresses:
an operation route first proves that the source representation was framed,
then an exact memory effect proves the bytes at a new base.
-/

def outcomeBulkCopy? : OutcomeExpr -> Option (BulkCopyExpr × Nat)
  | .bulkCopy copy continuationRva => some (copy, continuationRva)
  | _ => none

theorem engineRepAt_valid_at
    (valid : (engineRepAt layout sourceBase semantics).Valid) :
    (engineRepAt layout targetBase semantics).Valid := by
  rcases valid with ⟨layoutValid, slots, memoryValid, codeValid, dataValid⟩
  refine ⟨layoutValid, slots, ?_, codeValid, dataValid⟩
  constructor
  · intro originalLeft originalRight candidateAddress left
    simp [engineRepAt] at left
  · intro originalAddress candidateAddress mapped
    simp [engineRepAt] at mapped

theorem EngineStateHolds.preserveRepresentation
    (holds : EngineStateHolds layout base logical sourceRva before)
    (agrees :
      CandidateMemoryAgreesOnRepresentation
        (engineRepAt layout base before.x87Semantics)
        after.memory before.memory)
    (semantics : after.x87Semantics = before.x87Semantics) :
    EngineStateHolds layout base logical sourceRva after := by
  rcases holds with ⟨original, machineMatches, related⟩
  have agrees' :
      CandidateMemoryAgreesOnRepresentation
        (engineRepAt layout base original.x87Semantics)
        after.memory before.memory := by
    simpa [related.candidateSemantics] using agrees
  refine ⟨original, machineMatches, {
    repValid := related.repValid
    fields := ?_
    memory := ?_
    control := related.control
    originalSemantics := related.originalSemantics
    candidateSemantics := semantics.trans related.candidateSemantics
  }⟩
  · intro entry member
    have fieldsEqual :=
      readBytes_eq_of_candidate_memory_agreement agrees' entry member
    simp only [EngineFieldHolds] at *
    rw [fieldsEqual]
    exact related.fields entry member
  · intro originalAddress candidateAddress mapped
    simp [engineRepAt] at mapped

theorem EngineStateHolds.layoutValid
    (holds : EngineStateHolds layout base logical sourceRva state) :
    layout.Valid := by
  rcases holds with ⟨original, machineMatches, related⟩
  exact related.repValid.1

/-- Rebase a represented engine state after an exact byte copy. `fieldsCopied`
is deliberately byte-oriented so mixed-width x87 and selector fields are
covered by the same theorem as ordinary 32-bit registers. -/
theorem EngineStateHolds.rebase
    (holds : EngineStateHolds layout sourceBase logical sourceRva before)
    (fieldsCopied : ∀ entry ∈ layout.fields,
      readBytes after.memory (entry.address targetBase)
          entry.field.byteWidth =
        readBytes before.memory (entry.address sourceBase)
          entry.field.byteWidth)
    (semantics : after.x87Semantics = before.x87Semantics) :
    EngineStateHolds layout targetBase logical sourceRva after := by
  rcases holds with ⟨original, machineMatches, related⟩
  refine ⟨original, machineMatches, {
    repValid := engineRepAt_valid_at related.repValid
    fields := ?_
    memory := ?_
    control := related.control
    originalSemantics := related.originalSemantics
    candidateSemantics := semantics.trans related.candidateSemantics
  }⟩
  · intro entry member
    change entry ∈ layout.fields at member
    change some
        (readBytes after.memory (entry.address targetBase)
          entry.field.byteWidth) =
      (engineRepAt layout targetBase original.x87Semantics).fieldBytes
        original sourceRva entry.field
    rw [fieldsCopied entry member]
    simpa [EngineFieldHolds, engineRepAt] using related.fields entry member
  · intro originalAddress candidateAddress mapped
    simp [engineRepAt] at mapped

private theorem word_add_toNat_of_fits
    (base : Word) (offset : Nat)
    (fits : base.toNat + offset < 2 ^ 32) :
    (base + BitVec.ofNat 32 offset).toNat = base.toNat + offset := by
  have offsetFits : offset < 2 ^ 32 := by omega
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt offsetFits, Nat.mod_eq_of_lt fits]

/-- A non-wrapping concrete byte range used to protect an engine allocation
without expanding every field into a separate footprint atom. -/
def CandidateWordRange (base : Word) (size : Nat) : CandidateFootprint :=
  fun address =>
    base.toNat <= address.toNat ∧ address.toNat < base.toNat + size

theorem candidateAddressObserved_engineRepAt_in_wordRange
    (layout : EngineLayout) (base : Word)
    (semantics : StageA.X87.Semantics)
    (layoutValid : layout.Valid)
    (fits : base.toNat + layout.stateSize < 2 ^ 32) :
    ∀ address,
      CandidateAddressObserved (engineRepAt layout base semantics) address ->
        CandidateWordRange base layout.stateSize address := by
  intro address observed
  rcases observed with
    ⟨entry, member, byteOffset, byteBefore, addressExact⟩ |
      ⟨originalAddress, mapped⟩
  · have validFor : entry.ValidFor layout :=
      layoutValid.2.2.2.1 entry member
    have byteInside :
        entry.offset + byteOffset < layout.stateSize := by
      have fieldEnd :
          entry.offset + entry.field.byteWidth <= layout.stateSize :=
        validFor.2.2.2.1
      omega
    have addressForm :
        address =
          base + BitVec.ofNat 32 (entry.offset + byteOffset) := by
      simpa [engineRepAt, EngineFieldLayout.address, BitVec.add_assoc,
        ← BitVec.ofNat_add] using addressExact
    rw [addressForm]
    unfold CandidateWordRange
    rw [word_add_toNat_of_fits base
      (entry.offset + byteOffset) (by omega)]
    exact ⟨by omega, by omega⟩
  · simp [engineRepAt] at mapped

private theorem Memory.write32_apply_of_nat_outside
    (memory : Memory) (writeAddress value query : Word)
    (writeFits : writeAddress.toNat + 4 < 2 ^ 32)
    (outside :
      query.toNat < writeAddress.toNat ∨
        writeAddress.toNat + 4 <= query.toNat) :
    memory.write32 writeAddress value query = memory query := by
  have addressNat (offset : Nat) (before : offset < 4) :
      (writeAddress + BitVec.ofNat 32 offset).toNat =
        writeAddress.toNat + offset :=
    word_add_toNat_of_fits writeAddress offset (by omega)
  have different (offset : Nat) (before : offset < 4) :
      query ≠ writeAddress + BitVec.ofNat 32 offset := by
    intro equal
    have equalNat := congrArg BitVec.toNat equal
    rw [addressNat offset before] at equalNat
    omega
  have d0 : query ≠ writeAddress := by
    simpa using different 0 (by omega)
  have d1 : query ≠ writeAddress + BitVec.ofNat 32 1 :=
    different 1 (by omega)
  have d2 : query ≠ writeAddress + BitVec.ofNat 32 2 :=
    different 2 (by omega)
  have d3 : query ≠ writeAddress + BitVec.ofNat 32 3 :=
    different 3 (by omega)
  simp [Memory.write32, d0, d1, d2, d3]

private theorem Memory.write32_apply_inside
    (memory : Memory) (address value : Word)
    (fits : address.toNat + 4 < 2 ^ 32)
    (offset : Nat) (before : offset < 4) :
    memory.write32 address value (address + BitVec.ofNat 32 offset) =
      value.extractLsb' (offset * 8) 8 := by
  have h10 := word_add_small_ne address 1 0 (by omega : address.toNat + 4 <= 2 ^ 32)
    (by omega) (by omega) (by omega)
  have h20 := word_add_small_ne address 2 0 (by omega : address.toNat + 4 <= 2 ^ 32)
    (by omega) (by omega) (by omega)
  have h21 := word_add_small_ne address 2 1 (by omega : address.toNat + 4 <= 2 ^ 32)
    (by omega) (by omega) (by omega)
  have h30 := word_add_small_ne address 3 0 (by omega : address.toNat + 4 <= 2 ^ 32)
    (by omega) (by omega) (by omega)
  have h31 := word_add_small_ne address 3 1 (by omega : address.toNat + 4 <= 2 ^ 32)
    (by omega) (by omega) (by omega)
  have h32 := word_add_small_ne address 3 2 (by omega : address.toNat + 4 <= 2 ^ 32)
    (by omega) (by omega) (by omega)
  have cases : offset = 0 ∨ offset = 1 ∨ offset = 2 ∨ offset = 3 := by
    omega
  rcases cases with rfl | rfl | rfl | rfl <;>
    simp [Memory.write32, h10, h20, h21, h30, h31, h32]

private theorem Memory.read32_extractLsb8_at
    (memory : Memory) (address : Word) (offset : Nat)
    (before : offset < 4) :
    (Memory.read32 memory address).extractLsb' (offset * 8) 8 =
      memory (address + BitVec.ofNat 32 offset) := by
  have cases : offset = 0 ∨ offset = 1 ∨ offset = 2 ∨ offset = 3 := by
    omega
  rcases cases with rfl | rfl | rfl | rfl <;>
    unfold Memory.read32 <;>
    apply BitVec.eq_of_getLsbD_eq
  all_goals
    intro bit bitBefore
    have bitBefore16 : bit < 16 := by omega
    have bitBefore24 : bit < 24 := by omega
    have bitBefore32 : bit < 32 := by omega
    have shifted8Before16 : 8 + bit < 16 := by omega
    have shifted8Before24 : 8 + bit < 24 := by omega
    have shifted8Before32 : 8 + bit < 32 := by omega
    have shifted16Before24 : 16 + bit < 24 := by omega
    have shifted16Before32 : 16 + bit < 32 := by omega
    have shifted24Before32 : 24 + bit < 32 := by omega
    have shifted8After8 : ¬8 + bit < 8 := by omega
    have shifted16After8 : ¬16 + bit < 8 := by omega
    have shifted16After16 : ¬16 + bit < 16 := by omega
    have shifted24After8 : ¬24 + bit < 8 := by omega
    have shifted24After16 : ¬24 + bit < 16 := by omega
    have shifted24After24 : ¬24 + bit < 24 := by omega
    simp only [BitVec.getLsbD_extractLsb', BitVec.getLsbD_or,
      BitVec.getLsbD_shiftLeft, BitVec.getLsbD_setWidth]
    simp (disch := omega) [BitVec.getLsbD_of_ge,
      bitBefore, bitBefore16, bitBefore24, bitBefore32,
      shifted8Before16, shifted8Before24, shifted8Before32,
      shifted16Before24, shifted16Before32, shifted24Before32,
      shifted8After8, shifted16After8, shifted16After16,
      shifted24After8, shifted24After16, shifted24After24]

theorem Memory.bulkCopyDwords_apply_before
    (memory : Memory) (destination source query : Word) :
    ∀ count,
      destination.toNat + count * 4 < 2 ^ 32 ->
      query.toNat < destination.toNat ->
      Memory.bulkCopyDwords memory destination source false count query =
        memory query := by
  intro count
  induction count generalizing memory destination source with
  | zero =>
      intro _ _
      rfl
  | succ count induction =>
      intro fits before
      have destinationStep :
          (destination + BitVec.ofNat 32 4).toNat =
            destination.toNat + 4 :=
        word_add_toNat_of_fits destination 4 (by omega)
      simp only [Memory.bulkCopyDwords, Bool.false_eq_true, if_false]
      rw [induction]
      · exact Memory.write32_apply_of_nat_outside memory destination
          (Memory.read32 memory source) query (by omega) (Or.inl before)
      · rw [destinationStep]
        omega
      · rw [destinationStep]
        omega

theorem Memory.bulkCopyDwords_apply_after
    (memory : Memory) (destination source query : Word) :
    ∀ count,
      destination.toNat + count * 4 < 2 ^ 32 ->
      destination.toNat + count * 4 <= query.toNat ->
      Memory.bulkCopyDwords memory destination source false count query =
        memory query := by
  intro count
  induction count generalizing memory destination source with
  | zero =>
      intro _ _
      rfl
  | succ count induction =>
      intro fits after
      have destinationStep :
          (destination + BitVec.ofNat 32 4).toNat =
            destination.toNat + 4 :=
        word_add_toNat_of_fits destination 4 (by omega)
      simp only [Memory.bulkCopyDwords, Bool.false_eq_true, if_false]
      rw [induction]
      · exact Memory.write32_apply_of_nat_outside memory destination
          (Memory.read32 memory source) query (by omega) (Or.inr (by omega))
      · rw [destinationStep]
        omega
      · rw [destinationStep]
        omega

theorem Memory.bulkCopyDwords_forward_byte
    (memory : Memory) (destination source : Word) :
    ∀ count,
      destination.toNat + count * 4 < 2 ^ 32 ->
      source.toNat + count * 4 < 2 ^ 32 ->
      (source.toNat + count * 4 <= destination.toNat ∨
        destination.toNat + count * 4 <= source.toNat) ->
      ∀ offset, offset < count * 4 ->
        Memory.bulkCopyDwords memory destination source false count
            (destination + BitVec.ofNat 32 offset) =
          memory (source + BitVec.ofNat 32 offset) := by
  intro count
  induction count generalizing memory destination source with
  | zero =>
      intro _ _ _ offset before
      omega
  | succ count induction =>
      intro destinationFits sourceFits disjoint offset offsetBefore
      have destinationStep :
          (destination + BitVec.ofNat 32 4).toNat =
            destination.toNat + 4 :=
        word_add_toNat_of_fits destination 4 (by omega)
      have sourceStep :
          (source + BitVec.ofNat 32 4).toNat =
            source.toNat + 4 :=
        word_add_toNat_of_fits source 4 (by omega)
      simp only [Memory.bulkCopyDwords, Bool.false_eq_true, if_false]
      by_cases head : offset < 4
      · have queryNat :
            (destination + BitVec.ofNat 32 offset).toNat =
              destination.toNat + offset :=
          word_add_toNat_of_fits destination offset (by omega)
        have preserved :=
          Memory.bulkCopyDwords_apply_before
            (memory.write32 destination (Memory.read32 memory source))
            (destination + BitVec.ofNat 32 4)
            (source + BitVec.ofNat 32 4)
            (destination + BitVec.ofNat 32 offset)
            count (by rw [destinationStep]; omega)
            (by rw [queryNat, destinationStep]; omega)
        rw [preserved]
        rw [Memory.write32_apply_inside memory destination
          (Memory.read32 memory source) (by omega) offset head]
        exact Memory.read32_extractLsb8_at memory source offset head
      · obtain ⟨tailOffset, offsetExact⟩ :
            ∃ tailOffset, offset = 4 + tailOffset := by
          exact ⟨offset - 4, by omega⟩
        subst offset
        have tailBefore : tailOffset < count * 4 := by
          omega
        have tailDisjoint :
            (source + BitVec.ofNat 32 4).toNat + count * 4 <=
                (destination + BitVec.ofNat 32 4).toNat ∨
              (destination + BitVec.ofNat 32 4).toNat + count * 4 <=
                (source + BitVec.ofNat 32 4).toNat := by
          rw [sourceStep, destinationStep]
          omega
        have copied :=
          induction
            (memory := memory.write32 destination
              (Memory.read32 memory source))
            (destination := destination + BitVec.ofNat 32 4)
            (source := source + BitVec.ofNat 32 4)
            (by rw [destinationStep]; omega)
            (by rw [sourceStep]; omega)
            tailDisjoint tailOffset tailBefore
        have sourceQueryNat :
            (source + BitVec.ofNat 32 4 +
                BitVec.ofNat 32 tailOffset).toNat =
              source.toNat + 4 + tailOffset := by
          rw [BitVec.add_assoc, ← BitVec.ofNat_add]
          simpa [Nat.add_assoc] using
            word_add_toNat_of_fits source (4 + tailOffset) (by omega)
        have sourcePreserved :
            memory.write32 destination (Memory.read32 memory source)
                (source + BitVec.ofNat 32 4 +
                  BitVec.ofNat 32 tailOffset) =
              memory
                (source + BitVec.ofNat 32 4 +
                  BitVec.ofNat 32 tailOffset) := by
          apply Memory.write32_apply_of_nat_outside
          · omega
          · rw [sourceQueryNat]
            omega
        rw [sourcePreserved] at copied
        simpa [BitVec.add_assoc, ← BitVec.ofNat_add, Nat.add_assoc] using
          copied

theorem Engine.readBytes_bulkCopyDwords_forward
    (memory : Memory) (destination source : Word) (count offset width : Nat)
    (destinationFits : destination.toNat + count * 4 < 2 ^ 32)
    (sourceFits : source.toNat + count * 4 < 2 ^ 32)
    (disjoint :
      source.toNat + count * 4 <= destination.toNat ∨
        destination.toNat + count * 4 <= source.toNat)
    (inside : offset + width <= count * 4) :
    Engine.readBytes
        (Memory.bulkCopyDwords memory destination source false count)
        (destination + BitVec.ofNat 32 offset) width =
      Engine.readBytes memory
        (source + BitVec.ofNat 32 offset) width := by
  unfold Engine.readBytes
  apply List.map_congr_left
  intro byteOffset member
  have byteOffsetBefore : byteOffset < width :=
    List.mem_range.mp member
  have copied :=
    Memory.bulkCopyDwords_forward_byte memory destination source count
      destinationFits sourceFits disjoint (offset + byteOffset) (by omega)
  simpa [BitVec.add_assoc, ← BitVec.ofNat_add, Nat.add_assoc] using copied

/-- Rebase a complete engine representation through one checked forward
`rep movsd`.  The caller supplies only the ordinary range side conditions; the
field-by-field byte transport is discharged once here for every engine layout.
-/
theorem EngineStateHolds.rebase_bulkCopyDwords_forward
    (holds : EngineStateHolds layout source logical sourceRva before)
    (destinationFits : destination.toNat + count * 4 < 2 ^ 32)
    (sourceFits : source.toNat + count * 4 < 2 ^ 32)
    (disjoint :
      source.toNat + count * 4 <= destination.toNat ∨
        destination.toNat + count * 4 <= source.toNat)
    (covers : layout.stateSize <= count * 4)
    (destinationExact : destinationBase = destination)
    (memoryExact :
      after.memory =
        Memory.bulkCopyDwords before.memory destination source false count)
    (semantics : after.x87Semantics = before.x87Semantics) :
    EngineStateHolds layout destinationBase logical sourceRva after := by
  subst destinationBase
  have layoutValid : layout.Valid := by
    rcases holds with ⟨_, _, related⟩
    exact related.repValid.1
  apply EngineStateHolds.rebase holds
  · intro entry member
    rw [memoryExact]
    exact Engine.readBytes_bulkCopyDwords_forward before.memory destination source
      count entry.offset entry.field.byteWidth destinationFits sourceFits
      disjoint (by
        have validFor : entry.ValidFor layout :=
          layoutValid.2.2.2.1 entry member
        have fieldEnd :
            entry.offset + entry.field.byteWidth <= layout.stateSize :=
          validFor.2.2.2.1
        omega)
  · exact semantics

/-- Transport an engine-state witness through the exact target state computed
by a checked effectful `rep movsd` block.  The block checker owns execution and
control; this theorem owns only the byte-level representation transport. -/
theorem checkedNativeOperationEffectfulBlockStep_targetEngineStateHolds_bulkCopyDwords_forward
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {blocks : List
      (InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate)}
    {sourceBlock :
      InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate}
    {sourceInvariant :
      InterpreterKernelOperationCutpointChecker.NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock :
      InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (copy : BulkCopyExpr) (continuationRva : Nat)
    (outcomeExact : step.outcome = .bulkCopy copy continuationRva)
    (state : MachineState)
    (holds : EngineStateHolds layout sourceBase logical sourceRva
      (sourceBlock.terminal.after (sourceBlock.terminalState state)))
    (sourceExact :
      sourceBase =
        copy.source.eval (sourceBlock.terminalState state))
    (destinationExact :
      destinationBase =
        copy.destination.eval (sourceBlock.terminalState state))
    (directionExact :
      copy.direction.eval (sourceBlock.terminalState state) = false)
    (destinationFits :
      (copy.destination.eval (sourceBlock.terminalState state)).toNat +
          (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <
        2 ^ 32)
    (sourceFits :
      (copy.source.eval (sourceBlock.terminalState state)).toNat +
          (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <
        2 ^ 32)
    (disjoint :
      (copy.source.eval (sourceBlock.terminalState state)).toNat +
            (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <=
          (copy.destination.eval
            (sourceBlock.terminalState state)).toNat \/
        (copy.destination.eval (sourceBlock.terminalState state)).toNat +
            (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <=
          (copy.source.eval (sourceBlock.terminalState state)).toNat)
    (covers :
      layout.stateSize <=
        (copy.count.eval (sourceBlock.terminalState state)).toNat * 4) :
    EngineStateHolds layout destinationBase logical sourceRva
      (step.targetState state) := by
  have sourceHolds :
      EngineStateHolds layout
        (copy.source.eval (sourceBlock.terminalState state))
        logical sourceRva
        (sourceBlock.terminal.after (sourceBlock.terminalState state)) := by
    simpa [sourceExact] using holds
  apply EngineStateHolds.rebase_bulkCopyDwords_forward sourceHolds
  · exact destinationFits
  · exact sourceFits
  · exact disjoint
  · exact covers
  · exact destinationExact
  · simp [CheckedNativeOperationEffectfulBlockStep.targetState,
      nativeOperationLocalSuccessorState, outcomeExact, directionExact]
  · simp [CheckedNativeOperationEffectfulBlockStep.targetState,
      nativeOperationLocalSuccessorState, outcomeExact]

/-- Complete source-side facts needed to transport one represented engine
state through a checked forward bulk-copy block.  Keeping these facts in one
structure lets operation generators use the same relation at route boundaries
without reimplementing byte-copy reasoning. -/
structure ForwardEngineBulkCopySourceFacts
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    (sourceBlock :
      InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate)
    (copy : BulkCopyExpr) (layout : EngineLayout)
    (sourceBase destinationBase : Word)
    (logical : InterpreterMachine) (sourceRva : Nat)
    (state : MachineState) : Prop where
  holds : EngineStateHolds layout sourceBase logical sourceRva
    (sourceBlock.terminal.after (sourceBlock.terminalState state))
  sourceExact :
    sourceBase = copy.source.eval (sourceBlock.terminalState state)
  destinationExact :
    destinationBase = copy.destination.eval (sourceBlock.terminalState state)
  directionExact :
    copy.direction.eval (sourceBlock.terminalState state) = false
  destinationFits :
    (copy.destination.eval (sourceBlock.terminalState state)).toNat +
        (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <
      2 ^ 32
  sourceFits :
    (copy.source.eval (sourceBlock.terminalState state)).toNat +
        (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <
      2 ^ 32
  disjoint :
    (copy.source.eval (sourceBlock.terminalState state)).toNat +
          (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <=
        (copy.destination.eval (sourceBlock.terminalState state)).toNat ∨
      (copy.destination.eval (sourceBlock.terminalState state)).toNat +
          (copy.count.eval (sourceBlock.terminalState state)).toNat * 4 <=
        (copy.source.eval (sourceBlock.terminalState state)).toNat
  covers :
    layout.stateSize <=
      (copy.count.eval (sourceBlock.terminalState state)).toNat * 4

/-- Refine an already checked effectful block with engine-state source and
target relations.  All execution, control, frame, and graph fields are reused
from the exact block certificate; only the semantic relation is strengthened.
-/
def checkedNativeOperationEffectfulBlockStepWithForwardEngineState
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {blocks : List
      (InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate)}
    {sourceBlock :
      InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate}
    {sourceInvariant :
      InterpreterKernelOperationCutpointChecker.NativeOperationInvariant}
    {targetBlock :
      InterpreterKernelOperationTraceChecker.CheckedNativeOperationBlock
        candidate}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant (fun _ => True) targetBlock (fun _ => True))
    (copy : BulkCopyExpr) (continuationRva : Nat)
    (outcomeExact : step.outcome = .bulkCopy copy continuationRva)
    (layout : EngineLayout) (sourceBase destinationBase : Word)
    (logical : InterpreterMachine) (sourceRva : Nat) :
    CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant
      (ForwardEngineBulkCopySourceFacts sourceBlock copy layout sourceBase
        destinationBase logical sourceRva)
      targetBlock
      (EngineStateHolds layout destinationBase logical sourceRva) := {
  sourceMember := step.sourceMember
  targetMember := step.targetMember
  terminalInvariant := step.terminalInvariant
  prelude := step.prelude
  outcome := step.outcome
  outcomeExact := step.outcomeExact
  successor := step.successor
  successorChecked := step.successorChecked
  framesPreserved := step.framesPreserved
  alwaysRunningLocal := step.alwaysRunningLocal
  graphInvariantChecked := step.graphInvariantChecked
  targetRvaExact := step.targetRvaExact
  targetSlotExact := step.targetSlotExact
  targetRelationHolds := by
    intro state sourceHolds facts
    exact
      checkedNativeOperationEffectfulBlockStep_targetEngineStateHolds_bulkCopyDwords_forward
        step copy continuationRva outcomeExact state facts.holds
        facts.sourceExact facts.destinationExact facts.directionExact
        facts.destinationFits facts.sourceFits facts.disjoint facts.covers
}

#print axioms EngineStateHolds.preserveRepresentation
#print axioms EngineStateHolds.layoutValid
#print axioms EngineStateHolds.rebase
#print axioms EngineStateHolds.rebase_bulkCopyDwords_forward
#print axioms checkedNativeOperationEffectfulBlockStep_targetEngineStateHolds_bulkCopyDwords_forward
#print axioms checkedNativeOperationEffectfulBlockStepWithForwardEngineState
#print axioms engineRepAt_valid_at
#print axioms candidateAddressObserved_engineRepAt_in_wordRange
#print axioms Memory.bulkCopyDwords_apply_before
#print axioms Memory.bulkCopyDwords_apply_after
#print axioms Memory.bulkCopyDwords_forward_byte
#print axioms Engine.readBytes_bulkCopyDwords_forward

end StageA.Relational.InterpreterKernelEngineCopy
