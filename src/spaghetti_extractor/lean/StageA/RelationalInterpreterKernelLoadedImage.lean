import StageA.RelationalInterpreterKernelData
import StageA.RelationalMemory

namespace StageA.Relational.InterpreterKernelABI

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelData

/-!
# Loaded immutable candidate image

This module is the stable memory-facing boundary for exact interpreter data.
It deliberately excludes cdecl, operation, and whole-program composition
logic so PE-backed data projections do not import or invalidate that closure.
-/

def word32 (value : Nat) : Word := BitVec.ofNat 32 value

def byte8 (value : Nat) : BitVec 8 := BitVec.ofNat 8 value

def spanDisjoint (left right : Span) : Bool :=
  left.stop <= right.start || right.stop <= left.start

def spanContains (outer inner : Span) : Bool :=
  outer.start <= inner.start && inner.stop <= outer.stop

def addressInSpan (span : Span) (address : Word) : Prop :=
  span.start <= address.toNat ∧ address.toNat < span.stop ∧ span.stop <= 2 ^ 32

def addressRangeInSpan (span : Span) (address : Word) (size : Nat) : Prop :=
  ∀ offset, offset < size ->
    addressInSpan span (address + word32 offset)

/-! Exact loaded-image bytes. HIGHLOW relocation words are reconstructed from
PE bytes before selecting a byte. The native interpreter candidate is loaded at
its preferred image base, so immutable candidate ranges use the raw PE bytes. -/

def relocationCoversByte (relocation : BaseRelocation) (offset : Nat) : Bool :=
  relocation.rva <= offset && offset < relocation.rva + 4

def loadedRelocationWord? (pe : PE32) (loadBase : Nat)
    (relocation : BaseRelocation) : Option Nat := do
  let preferred <- readRvaU32 pe relocation.rva
  pure ((preferred + loadBase + 2 ^ 32 - pe.imageBase) % (2 ^ 32))

def loadedImageByte? (pe : PE32) (relocations : List BaseRelocation)
    (loadBase offset : Nat) : Option Nat :=
  match relocations.find? fun relocation =>
      relocationCoversByte relocation offset with
  | none => rvaByte pe offset
  | some relocation => do
      let value <- loadedRelocationWord? pe loadBase relocation
      pure ((value / 2 ^ (8 * (offset - relocation.rva))) % 256)

def relocationLayoutChecked (pe : PE32)
    (relocations : List BaseRelocation) : Bool :=
  relocationInventoryUnique relocations &&
    relocations.all fun relocation =>
      relocation.kind == 3 && relocation.rva % 4 == 0 &&
        relocation.rva + 4 <= pe.sizeOfImage

def LoadedSpanHolds (pe : PE32) (relocations : List BaseRelocation)
    (loadBase : Nat) (span : Span) (memory : Memory) : Prop :=
  ∀ offset, offset < span.size -> ∀ expected,
    loadedImageByte? pe relocations loadBase (span.start + offset) =
        some expected ->
      memory (word32 (loadBase + span.start + offset)) = byte8 expected

def LoadedCandidateImageMemory (pe : PE32) (imports : List PEImport)
    (_relocations : List BaseRelocation) (memory : Memory) : Prop :=
  ∀ rva size bytes,
    immutableRvaBytes pe imports rva size = some bytes ->
      ∀ offset expected, offset < size -> bytes[offset]? = some expected ->
        memory (word32 (pe.imageBase + rva + offset)) = byte8 expected

theorem immutableRvaBytes_bounded
    (exact : immutableRvaBytes pe imports rva size = some bytes) :
    rva + size <= pe.sizeOfImage := by
  unfold immutableRvaBytes at exact
  split at exact
  next => contradiction
  next accepted =>
    by_cases bounded : rva + size <= pe.sizeOfImage
    · exact bounded
    · exfalso
      apply accepted
      have tooLarge : rva + size > pe.sizeOfImage :=
        Nat.lt_of_not_ge bounded
      simp [tooLarge]

end StageA.Relational.InterpreterKernelABI
