import StageA.RelationalInterpreterKernelLoadedImage

namespace StageA.Relational.InterpreterKernelProgramTableProjection

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData

/-!
# Native projections of the checked interpreter program table

`ProgramTableCertificate` proves that the semantic records were decoded from
the candidate PE.  The native interpreter subsequently reads the same bytes
through flat machine memory.  This module is the stable bridge between those
two views.

The compatibility checkers below can recompute bytes from the exact PE.  The
scalable path instead consumes exact `ImmutableByteRange` authorities emitted
by the data proof: each descriptor and action array is reduced once against its
small local byte range, and the soundness theorems project those bytes through
`LoadedCandidateImageMemory`.
-/

/-- One immutable byte together with its value after applying the checked
loader relocation model.  Retaining the raw byte makes the immutable-image
premise explicit instead of treating `loadedImageByte?` as an authority by
itself. -/
def loadedCandidateByte? (pe : PE32) (imports : List PEImport)
    (_relocations : List BaseRelocation) (rva : Nat) :
    Option (Nat × Nat) :=
  match immutableRvaBytes pe imports rva 1 with
  | some [raw] =>
      if raw < 256 then some (raw, raw) else none
  | _ => none

theorem LoadedCandidateImageMemory.byte_of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (checked :
      loadedCandidateByte? pe imports relocations rva = some (raw, expected)) :
    memory (word32 (pe.imageBase + rva)) = byte8 expected ∧ expected < 256 := by
  unfold loadedCandidateByte? at checked
  split at checked
  next rawBytes immutableExact =>
    split at checked
    next bounded =>
      have pairExact := Option.some.inj checked
      injection pairExact with rawExact expectedExact
      subst raw
      subst expected
      exact ⟨loaded rva 1 [rawBytes] immutableExact 0 rawBytes
        (by omega) (by simp), bounded⟩
    next _ =>
      contradiction
  next =>
    contradiction

/-- Assemble one loaded little-endian word only after all four source bytes
and all four relocated bytes have been recomputed. -/
def loadedCandidateWord? (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (rva : Nat) : Option Nat := do
  let byte0 <- loadedCandidateByte? pe imports relocations rva
  let byte1 <- loadedCandidateByte? pe imports relocations (rva + 1)
  let byte2 <- loadedCandidateByte? pe imports relocations (rva + 2)
  let byte3 <- loadedCandidateByte? pe imports relocations (rva + 3)
  pure (byte0.2 + byte1.2 * 256 + byte2.2 * 65536 +
    byte3.2 * 16777216)

theorem LoadedCandidateImageMemory.read32_of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (checked :
      loadedCandidateWord? pe imports relocations rva = some expected) :
    Memory.read32 memory (word32 (pe.imageBase + rva)) = word32 expected := by
  unfold loadedCandidateWord? at checked
  cases byte0Exact :
      loadedCandidateByte? pe imports relocations rva with
  | none =>
      simp [byte0Exact] at checked
  | some byte0 =>
    cases byte1Exact :
        loadedCandidateByte? pe imports relocations (rva + 1) with
    | none =>
        simp [byte0Exact, byte1Exact] at checked
    | some byte1 =>
      cases byte2Exact :
          loadedCandidateByte? pe imports relocations (rva + 2) with
      | none =>
          simp [byte0Exact, byte1Exact, byte2Exact] at checked
      | some byte2 =>
        cases byte3Exact :
            loadedCandidateByte? pe imports relocations (rva + 3) with
        | none =>
            simp [byte0Exact, byte1Exact, byte2Exact, byte3Exact] at checked
        | some byte3 =>
          have expectedExact :
              byte0.2 + byte1.2 * 256 + byte2.2 * 65536 +
                  byte3.2 * 16777216 =
                expected := by
            simpa [byte0Exact, byte1Exact, byte2Exact, byte3Exact] using checked
          have loaded0 :=
            LoadedCandidateImageMemory.byte_of_checked loaded byte0Exact
          have loaded1 :=
            LoadedCandidateImageMemory.byte_of_checked loaded byte1Exact
          have loaded2 :=
            LoadedCandidateImageMemory.byte_of_checked loaded byte2Exact
          have loaded3 :=
            LoadedCandidateImageMemory.byte_of_checked loaded byte3Exact
          unfold Memory.read32
          rw [loaded0.1]
          rw [show
            word32 (pe.imageBase + rva) + BitVec.ofNat 32 1 =
              word32 (pe.imageBase + (rva + 1)) by
                simp [word32, Nat.add_assoc, ← BitVec.ofNat_add]]
          rw [loaded1.1]
          rw [show
            word32 (pe.imageBase + rva) + BitVec.ofNat 32 2 =
              word32 (pe.imageBase + (rva + 2)) by
                simp [word32, Nat.add_assoc, ← BitVec.ofNat_add]]
          rw [loaded2.1]
          rw [show
            word32 (pe.imageBase + rva) + BitVec.ofNat 32 3 =
              word32 (pe.imageBase + (rva + 3)) by
                simp [word32, Nat.add_assoc, ← BitVec.ofNat_add]]
          rw [loaded3.1]
          simpa [expectedExact] using
            fourBytesAssembleLittleEndian byte0.2 byte1.2 byte2.2
              byte3.2 loaded0.2 loaded1.2 loaded2.2 loaded3.2

private theorem readByte_eq_indexed (bytes : Bytes) (offset : Nat) :
    readByte bytes offset = bytes[offset]? := by
  simp [readByte]

private theorem readU16_components
    (exact : readU16 bytes offset = some expected) :
    ∃ byte0 byte1,
      bytes[offset]? = some byte0 ∧
      bytes[offset + 1]? = some byte1 ∧
      byte0 < 256 ∧ byte1 < 256 ∧
      expected = byte0 + byte1 * 256 := by
  unfold readU16 at exact
  cases byte0Exact : readByte bytes offset with
  | none => simp [byte0Exact] at exact
  | some byte0 =>
    cases byte1Exact : readByte bytes (offset + 1) with
    | none => simp [byte0Exact, byte1Exact] at exact
    | some byte1 =>
      by_cases byte0Bounded : byte0 < 256
      · by_cases byte1Bounded : byte1 < 256
        · simp [byte0Exact, byte1Exact, byte0Bounded, byte1Bounded] at exact
          subst expected
          exact ⟨byte0, byte1,
            readByte_eq_indexed bytes offset ▸ byte0Exact,
            readByte_eq_indexed bytes (offset + 1) ▸ byte1Exact,
            byte0Bounded, byte1Bounded, rfl⟩
        · simp [byte0Exact, byte1Exact, byte1Bounded] at exact
      · simp [byte0Exact, byte1Exact, byte0Bounded] at exact

/-- A word check over a compact exact byte range.  This is the preferred
generated-certificate boundary: reduction is proportional to the local range,
not to the complete PE/import/relocation inventories. -/
def immutableRangeWordChecked (range : ImmutableByteRange)
    (offset expected : Nat) : Bool :=
  decide (offset + 4 <= range.size) &&
    readU32 range.bytes offset == some expected

def immutableRangeWordsChecked (range : ImmutableByteRange) :
    Nat -> List Nat -> Bool
  | _, [] => true
  | offset, value :: tail =>
      immutableRangeWordChecked range offset value &&
        immutableRangeWordsChecked range (offset + 4) tail

theorem LoadedCandidateImageMemory.read32_of_range_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (rangeExact :
      immutableRvaBytes pe imports range.rva range.size = some range.bytes)
    (checked : immutableRangeWordChecked range offset expected = true) :
    Memory.read32 memory
        (word32 (pe.imageBase + range.rva + offset)) =
      word32 expected := by
  simp only [immutableRangeWordChecked, Bool.and_eq_true, decide_eq_true_eq,
    beq_iff_eq] at checked
  rcases checked with ⟨bounded, wordExact⟩
  unfold readU32 at wordExact
  cases lowExact : readU16 range.bytes offset with
  | none => simp [lowExact] at wordExact
  | some low =>
    cases highExact : readU16 range.bytes (offset + 2) with
    | none => simp [lowExact, highExact] at wordExact
    | some high =>
      have expectedExact : low + high * 65536 = expected := by
        simpa [lowExact, highExact] using wordExact
      rcases readU16_components lowExact with
        ⟨byte0, byte1, byte0Exact, byte1Exact, byte0Bounded, byte1Bounded,
          lowValue⟩
      rcases readU16_components highExact with
        ⟨byte2, byte3, byte2Exact, byte3Exact, byte2Bounded, byte3Bounded,
          highValue⟩
      have loaded0 := loaded range.rva range.size range.bytes rangeExact
        offset byte0 (by omega) byte0Exact
      have loaded1 := loaded range.rva range.size range.bytes rangeExact
        (offset + 1) byte1 (by omega) byte1Exact
      have loaded2 := loaded range.rva range.size range.bytes rangeExact
        (offset + 2) byte2 (by omega) byte2Exact
      have loaded3 := loaded range.rva range.size range.bytes rangeExact
        (offset + 3) byte3 (by omega) (by
          simpa [Nat.add_assoc] using byte3Exact)
      unfold Memory.read32
      rw [loaded0]
      rw [show
        word32 (pe.imageBase + range.rva + offset) + BitVec.ofNat 32 1 =
          word32 (pe.imageBase + range.rva + (offset + 1)) by
            simp [word32, Nat.add_assoc, ← BitVec.ofNat_add]]
      rw [loaded1]
      rw [show
        word32 (pe.imageBase + range.rva + offset) + BitVec.ofNat 32 2 =
          word32 (pe.imageBase + range.rva + (offset + 2)) by
            simp [word32, Nat.add_assoc, ← BitVec.ofNat_add]]
      rw [loaded2]
      rw [show
        word32 (pe.imageBase + range.rva + offset) + BitVec.ofNat 32 3 =
          word32 (pe.imageBase + range.rva + (offset + 3)) by
            simp [word32, Nat.add_assoc, ← BitVec.ofNat_add]]
      rw [loaded3]
      rw [← expectedExact, lowValue, highValue]
      rw [show
        byte0 + byte1 * 256 +
            ((byte2 + byte3 * 256) * 65536) =
          byte0 + byte1 * 256 + byte2 * 65536 +
            byte3 * 16777216 by
              simp [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]]
      simpa [word32, byte8] using
        fourBytesAssembleLittleEndian byte0 byte1 byte2 byte3
          byte0Bounded byte1Bounded byte2Bounded byte3Bounded

theorem LoadedCandidateImageMemory.words_of_range_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (rangeExact :
      immutableRvaBytes pe imports range.rva range.size = some range.bytes) :
    ∀ offset values,
      immutableRangeWordsChecked range offset values = true ->
      ∀ index value, values[index]? = some value ->
        Memory.read32 memory
            (word32 (pe.imageBase + range.rva + offset + index * 4)) =
          word32 value := by
  intro offset values
  induction values generalizing offset with
  | nil =>
      intro _ index value indexed
      simp at indexed
  | cons head tail induction =>
      intro checked index value indexed
      simp only [immutableRangeWordsChecked, Bool.and_eq_true] at checked
      cases index with
      | zero =>
          simp at indexed
          subst value
          simpa [Nat.add_assoc] using
            LoadedCandidateImageMemory.read32_of_range_checked loaded rangeExact
              checked.1
      | succ index =>
          simp at indexed
          have tailExact :=
            induction (offset := offset + 4) checked.2 index value indexed
          simpa [Nat.succ_mul, Nat.add_assoc, Nat.add_comm,
            Nat.add_left_comm] using tailExact

/-- Check the ten fixed-width fields of one compiled transfer descriptor
against the exact loaded candidate image. -/
def transferDescriptorLoadedChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (descriptor : TransferDescriptor) : Bool :=
  let base := tableRva + index * transferRecordSize
  loadedCandidateWord? pe imports relocations base ==
      some descriptor.sourceRva &&
    loadedCandidateWord? pe imports relocations (base + 4) ==
      some descriptor.wordCount &&
    loadedCandidateWord? pe imports relocations (base + 8) ==
      some descriptor.x87Count &&
    loadedCandidateWord? pe imports relocations (base + 12) ==
      some descriptor.actionCount &&
    loadedCandidateWord? pe imports relocations (base + 16) ==
      some descriptor.replayCount &&
    loadedCandidateWord? pe imports relocations (base + 20) ==
      some descriptor.wordPointer &&
    loadedCandidateWord? pe imports relocations (base + 24) ==
      some descriptor.x87Pointer &&
    loadedCandidateWord? pe imports relocations (base + 28) ==
      some descriptor.actionPointer &&
    loadedCandidateWord? pe imports relocations (base + 32) ==
      some descriptor.callPointer &&
    loadedCandidateWord? pe imports relocations (base + 36) ==
      some descriptor.replayPointer

def transferDescriptorValues (descriptor : TransferDescriptor) : List Nat := [
  descriptor.sourceRva,
  descriptor.wordCount,
  descriptor.x87Count,
  descriptor.actionCount,
  descriptor.replayCount,
  descriptor.wordPointer,
  descriptor.x87Pointer,
  descriptor.actionPointer,
  descriptor.callPointer,
  descriptor.replayPointer
]

def transferDescriptorRangeChecked (range : ImmutableByteRange)
    (tableRva index : Nat) (descriptor : TransferDescriptor) : Bool :=
  let base := tableRva + index * transferRecordSize
  decide (range.rva = base) &&
    decide (range.size = transferRecordSize) &&
    immutableRangeWordsChecked range 0 (transferDescriptorValues descriptor)

/-- The exact machine-memory view consumed by `stage_b_interpreter_step`.
Every field is derived from `transferDescriptorLoadedChecked`; generated code
cannot provide a replacement field value. -/
structure LoadedTransferDescriptorAt
    (pe : PE32) (tableRva index : Nat) (descriptor : TransferDescriptor)
    (memory : Memory) : Prop where
  sourceRva :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize)) =
      word32 descriptor.sourceRva
  wordCount :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 4)) =
      word32 descriptor.wordCount
  x87Count :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 8)) =
      word32 descriptor.x87Count
  actionCount :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 12)) =
      word32 descriptor.actionCount
  replayCount :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 16)) =
      word32 descriptor.replayCount
  wordPointer :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 20)) =
      word32 descriptor.wordPointer
  x87Pointer :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 24)) =
      word32 descriptor.x87Pointer
  actionPointer :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 28)) =
      word32 descriptor.actionPointer
  callPointer :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 32)) =
      word32 descriptor.callPointer
  replayPointer :
    Memory.read32 memory
        (word32 (pe.imageBase + tableRva + index * transferRecordSize + 36)) =
      word32 descriptor.replayPointer

def LoadedTransferDescriptorAt.of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (checked :
      transferDescriptorLoadedChecked pe imports relocations tableRva index
        descriptor = true) :
    LoadedTransferDescriptorAt pe tableRva index descriptor memory := by
  simp only [transferDescriptorLoadedChecked, Bool.and_eq_true, beq_iff_eq]
    at checked
  let base := tableRva + index * transferRecordSize
  refine {
    sourceRva := ?_
    wordCount := ?_
    x87Count := ?_
    actionCount := ?_
    replayCount := ?_
    wordPointer := ?_
    x87Pointer := ?_
    actionPointer := ?_
    callPointer := ?_
    replayPointer := ?_
  }
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded
        checked.1.1.1.1.1.1.1.1.1
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded
        checked.1.1.1.1.1.1.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded
        checked.1.1.1.1.1.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded
        checked.1.1.1.1.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded
        checked.1.1.1.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded
        checked.1.1.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded checked.1.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded checked.1.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded checked.1.2
  · simpa [base, Nat.add_assoc] using
      LoadedCandidateImageMemory.read32_of_checked loaded checked.2

def LoadedTransferDescriptorAt.of_range_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (rangeExact :
      immutableRvaBytes pe imports range.rva range.size = some range.bytes)
    (checked :
      transferDescriptorRangeChecked range tableRva index descriptor = true) :
    LoadedTransferDescriptorAt pe tableRva index descriptor memory := by
  simp only [transferDescriptorRangeChecked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with ⟨⟨rangeRva, rangeSize⟩, wordsChecked⟩
  have wordAt (index value : Nat)
      (indexed : (transferDescriptorValues descriptor)[index]? = some value) :
      Memory.read32 memory
          (word32 (pe.imageBase + range.rva + index * 4)) =
        word32 value :=
    LoadedCandidateImageMemory.words_of_range_checked loaded rangeExact 0
      (transferDescriptorValues descriptor) wordsChecked index value indexed
  exact {
    sourceRva := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 0 descriptor.sourceRva (by rfl)
    wordCount := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 1 descriptor.wordCount (by rfl)
    x87Count := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 2 descriptor.x87Count (by rfl)
    actionCount := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 3 descriptor.actionCount (by rfl)
    replayCount := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 4 descriptor.replayCount (by rfl)
    wordPointer := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 5 descriptor.wordPointer (by rfl)
    x87Pointer := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 6 descriptor.x87Pointer (by rfl)
    actionPointer := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 7 descriptor.actionPointer (by rfl)
    callPointer := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 8 descriptor.callPointer (by rfl)
    replayPointer := by
      simpa [rangeRva, transferDescriptorValues, Nat.add_assoc] using
        wordAt 9 descriptor.replayPointer (by rfl)
  }

/-- Recursive checker for a native array of 32-bit words. -/
def loadedCandidateWordsChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) : Nat -> List Nat -> Bool
  | _, [] => true
  | rva, value :: tail =>
      loadedCandidateWord? pe imports relocations rva == some value &&
        loadedCandidateWordsChecked pe imports relocations (rva + 4) tail

theorem LoadedCandidateImageMemory.words_of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory) :
    ∀ rva values,
      loadedCandidateWordsChecked pe imports relocations rva values = true ->
      ∀ index value, values[index]? = some value ->
        Memory.read32 memory
            (word32 (pe.imageBase + rva + index * 4)) =
          word32 value := by
  intro rva values
  induction values generalizing rva with
  | nil =>
      intro _ index value indexed
      simp at indexed
  | cons head tail induction =>
      intro checked index value indexed
      simp only [loadedCandidateWordsChecked, Bool.and_eq_true, beq_iff_eq]
        at checked
      cases index with
      | zero =>
          simp at indexed
          subst value
          simpa using
            LoadedCandidateImageMemory.read32_of_checked loaded checked.1
      | succ index =>
          simp at indexed
          have tailExact :=
            induction (rva := rva + 4) checked.2 index value indexed
          simpa [Nat.succ_mul, Nat.add_assoc, Nat.add_comm,
            Nat.add_left_comm] using tailExact

/-- Check the fields retained by the typed `RawAction`.  Unused C padding
arguments are intentionally excluded; the native interpreter can only read
arguments admitted by the action's checked arity and semantic constructor. -/
def rawActionLoadedChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (actionRva : Nat)
    (action : RawAction) : Bool :=
  loadedCandidateWord? pe imports relocations actionRva == some action.op &&
    loadedCandidateWord? pe imports relocations (actionRva + 4) ==
      some action.arity &&
    loadedCandidateWord? pe imports relocations (actionRva + 8) ==
      some action.aux &&
    loadedCandidateWordsChecked pe imports relocations (actionRva + 12)
      action.args

def rawActionRangeChecked (range : ImmutableByteRange)
    (offset : Nat) (action : RawAction) : Bool :=
  immutableRangeWordChecked range offset action.op &&
    immutableRangeWordChecked range (offset + 4) action.arity &&
    immutableRangeWordChecked range (offset + 8) action.aux &&
    immutableRangeWordsChecked range (offset + 12) action.args

structure LoadedRawActionAt (pe : PE32) (actionRva : Nat)
    (action : RawAction) (memory : Memory) : Prop where
  op :
    Memory.read32 memory (word32 (pe.imageBase + actionRva)) =
      word32 action.op
  arity :
    Memory.read32 memory (word32 (pe.imageBase + actionRva + 4)) =
      word32 action.arity
  aux :
    Memory.read32 memory (word32 (pe.imageBase + actionRva + 8)) =
      word32 action.aux
  argument : ∀ index value, action.args[index]? = some value ->
    Memory.read32 memory
        (word32 (pe.imageBase + actionRva + 12 + index * 4)) =
      word32 value

def LoadedRawActionAt.of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (checked :
      rawActionLoadedChecked pe imports relocations actionRva action = true) :
    LoadedRawActionAt pe actionRva action memory := by
  simp only [rawActionLoadedChecked, Bool.and_eq_true, beq_iff_eq] at checked
  exact {
    op := LoadedCandidateImageMemory.read32_of_checked loaded checked.1.1.1
    arity := by
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.read32_of_checked loaded checked.1.1.2
    aux := by
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.read32_of_checked loaded checked.1.2
    argument := by
      intro index value indexed
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.words_of_checked loaded
          (actionRva + 12) action.args checked.2 index value indexed
  }

def LoadedRawActionAt.of_range_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (rangeExact :
      immutableRvaBytes pe imports range.rva range.size = some range.bytes)
    (checked : rawActionRangeChecked range offset action = true) :
    LoadedRawActionAt pe (range.rva + offset) action memory := by
  simp only [rawActionRangeChecked, Bool.and_eq_true] at checked
  exact {
    op := by
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.read32_of_range_checked loaded rangeExact
          checked.1.1.1
    arity := by
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.read32_of_range_checked loaded rangeExact
          checked.1.1.2
    aux := by
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.read32_of_range_checked loaded rangeExact
          checked.1.2
    argument := by
      intro index value indexed
      simpa [Nat.add_assoc] using
        LoadedCandidateImageMemory.words_of_range_checked loaded rangeExact
          (offset + 12) action.args checked.2 index value indexed
  }

/-- Check a complete fixed-stride native action array once.  Downstream Step
proofs use the indexed certificate below and never recompute the PE reads for
an individual loop iteration. -/
def rawActionArrayLoadedChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) : Nat -> List RawAction -> Bool
  | _, [] => true
  | actionRva, action :: tail =>
      rawActionLoadedChecked pe imports relocations actionRva action &&
        rawActionArrayLoadedChecked pe imports relocations
          (actionRva + actionSize) tail

def rawActionArrayRangeChecked (range : ImmutableByteRange) :
    Nat -> List RawAction -> Bool
  | _, [] => true
  | offset, action :: tail =>
      rawActionRangeChecked range offset action &&
        rawActionArrayRangeChecked range (offset + actionSize) tail

structure LoadedRawActionArrayAt (pe : PE32) (actionRva : Nat)
    (actions : List RawAction) (memory : Memory) : Prop where
  action : ∀ index rawAction, actions[index]? = some rawAction ->
    LoadedRawActionAt pe (actionRva + index * actionSize) rawAction memory

def LoadedRawActionArrayAt.of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory) :
    ∀ actionRva actions,
      rawActionArrayLoadedChecked pe imports relocations actionRva actions =
          true ->
        LoadedRawActionArrayAt pe actionRva actions memory := by
  intro actionRva actions
  induction actions generalizing actionRva with
  | nil =>
      intro _
      exact { action := by intro index rawAction indexed; simp at indexed }
  | cons head tail induction =>
      intro checked
      simp only [rawActionArrayLoadedChecked, Bool.and_eq_true] at checked
      refine { action := ?_ }
      intro index rawAction indexed
      cases index with
      | zero =>
          simp at indexed
          subst rawAction
          simpa using LoadedRawActionAt.of_checked loaded checked.1
      | succ index =>
          simp at indexed
          have tailLoaded :=
            (induction (actionRva := actionRva + actionSize) checked.2).action
              index rawAction indexed
          simpa [Nat.succ_mul, Nat.add_assoc, Nat.add_comm,
            Nat.add_left_comm] using tailLoaded

def LoadedRawActionArrayAt.of_range_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (rangeExact :
      immutableRvaBytes pe imports range.rva range.size = some range.bytes) :
    ∀ offset actions,
      rawActionArrayRangeChecked range offset actions = true ->
        LoadedRawActionArrayAt pe (range.rva + offset) actions memory := by
  intro offset actions
  induction actions generalizing offset with
  | nil =>
      intro _
      exact { action := by intro index rawAction indexed; simp at indexed }
  | cons head tail induction =>
      intro checked
      simp only [rawActionArrayRangeChecked, Bool.and_eq_true] at checked
      refine { action := ?_ }
      intro index rawAction indexed
      cases index with
      | zero =>
          simp at indexed
          subst rawAction
          simpa [Nat.add_assoc] using
            LoadedRawActionAt.of_range_checked loaded rangeExact checked.1
      | succ index =>
          simp at indexed
          have tailLoaded :=
            (induction (offset := offset + actionSize) checked.2).action
              index rawAction indexed
          simpa [Nat.succ_mul, Nat.add_assoc, Nat.add_comm,
            Nat.add_left_comm] using tailLoaded

/-- Check the native action-bearing part of one transfer.  The descriptor,
pointer translation, count, and full fixed-stride action array are one
certificate so a semantic record cannot be paired with another record's
native array. -/
def transferActionsLoadedChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (data : TransferCertificateData) : Bool :=
  transferDescriptorLoadedChecked pe imports relocations tableRva index
      data.descriptor &&
    decide (data.descriptor.actionCount = data.actions.length) &&
    match absoluteImageVaToRva pe data.descriptor.actionPointer with
    | none => false
    | some actionRva =>
        rawActionArrayLoadedChecked pe imports relocations actionRva data.actions

def transferActionsRangesChecked (pe : PE32) (tableRva index : Nat)
    (data : TransferCertificateData) (descriptorRange actionRange :
      ImmutableByteRange) : Bool :=
  transferDescriptorRangeChecked descriptorRange tableRva index data.descriptor &&
    decide (data.descriptor.actionCount = data.actions.length) &&
    match absoluteImageVaToRva pe data.descriptor.actionPointer with
    | none => false
    | some actionRva =>
        decide (actionRange.rva = actionRva) &&
          decide (actionRange.size = data.actions.length * actionSize) &&
          rawActionArrayRangeChecked actionRange 0 data.actions

structure LoadedTransferActionsAt
    (pe : PE32) (tableRva index : Nat) (data : TransferCertificateData)
    (memory : Memory) where
  descriptor :
    LoadedTransferDescriptorAt pe tableRva index data.descriptor memory
  actionCount : data.descriptor.actionCount = data.actions.length
  actionRva : Nat
  actionPointer :
    absoluteImageVaToRva pe data.descriptor.actionPointer = some actionRva
  actions : LoadedRawActionArrayAt pe actionRva data.actions memory

def LoadedTransferActionsAt.of_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (checked :
      transferActionsLoadedChecked pe imports relocations tableRva index data =
        true) :
    LoadedTransferActionsAt pe tableRva index data memory := by
  simp only [transferActionsLoadedChecked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with ⟨⟨descriptorChecked, countExact⟩, actionsChecked⟩
  cases actionRvaExact :
      absoluteImageVaToRva pe data.descriptor.actionPointer with
  | none =>
      simp [actionRvaExact] at actionsChecked
  | some actionRva =>
      exact {
        descriptor := LoadedTransferDescriptorAt.of_checked loaded
          descriptorChecked
        actionCount := countExact
        actionRva := actionRva
        actionPointer := actionRvaExact
        actions := LoadedRawActionArrayAt.of_checked loaded actionRva
          data.actions (by simpa [actionRvaExact] using actionsChecked)
      }

def LoadedTransferActionsAt.of_ranges_checked
    (loaded : LoadedCandidateImageMemory pe imports relocations memory)
    (descriptorExact : immutableRvaBytes pe imports descriptorRange.rva
      descriptorRange.size = some descriptorRange.bytes)
    (actionExact : immutableRvaBytes pe imports actionRange.rva
      actionRange.size = some actionRange.bytes)
    (checked :
      transferActionsRangesChecked pe tableRva index data descriptorRange
        actionRange = true) :
    LoadedTransferActionsAt pe tableRva index data memory := by
  simp only [transferActionsRangesChecked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  rcases checked with
    ⟨⟨descriptorChecked, countExact⟩, actionsChecked⟩
  cases actionRvaExact :
      absoluteImageVaToRva pe data.descriptor.actionPointer with
  | none =>
      simp [actionRvaExact] at actionsChecked
  | some actionRva =>
      simp only [actionRvaExact, Bool.and_eq_true, decide_eq_true_eq]
        at actionsChecked
      exact {
        descriptor := LoadedTransferDescriptorAt.of_range_checked loaded
          descriptorExact descriptorChecked
        actionCount := countExact
        actionRva := actionRva
        actionPointer := actionRvaExact
        actions := by
          have loadedActions :=
            LoadedRawActionArrayAt.of_range_checked loaded actionExact 0
              data.actions actionsChecked.2
          simpa [actionsChecked.1.1, Nat.add_assoc] using loadedActions
      }

#print axioms LoadedCandidateImageMemory.byte_of_checked
#print axioms LoadedCandidateImageMemory.read32_of_checked
#print axioms LoadedCandidateImageMemory.read32_of_range_checked
#print axioms LoadedTransferDescriptorAt.of_checked
#print axioms LoadedTransferDescriptorAt.of_range_checked
#print axioms LoadedCandidateImageMemory.words_of_checked
#print axioms LoadedCandidateImageMemory.words_of_range_checked
#print axioms LoadedRawActionAt.of_checked
#print axioms LoadedRawActionAt.of_range_checked
#print axioms LoadedRawActionArrayAt.of_checked
#print axioms LoadedRawActionArrayAt.of_range_checked
#print axioms LoadedTransferActionsAt.of_checked
#print axioms LoadedTransferActionsAt.of_ranges_checked

end StageA.Relational.InterpreterKernelProgramTableProjection
