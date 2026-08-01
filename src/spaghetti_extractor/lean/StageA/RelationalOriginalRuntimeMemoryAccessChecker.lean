import StageA.RelationalOriginalRuntimeMemoryPartition
import StageA.RelationalOriginalStaticWordExecutionInvariant

namespace StageA.Relational.OriginalRuntimeMemoryAccessChecker

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalStaticWordExecutionInvariant

/-!
# Checked normalized runtime-memory accesses

This module is the reflective boundary between untrusted address-provenance
proposals and original-side memory preservation.  It checks an exact write in
the normalized behavior, its exact affine address expression, and a concrete
range in the current relational world.  The soundness theorem then produces
the existing `OriginalRuntimeAccessWitness`; the runtime partition supplies
non-wrapping and protected-image disjointness.

There is no unknown access certificate.  Static writes require an explicit
post-update `OriginalStaticWordRequirement.Holds` proof, and an empty write
inventory is accepted only when the exact normalized list is empty.
-/

/-- A stable reference to one exact normalized 32-bit write. -/
structure OriginalNormalizedWriteReference where
  index : Nat
  address : Expr
  value : Expr
deriving Repr, DecidableEq

def exactNormalizedWriteChecked (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference) : Bool :=
  writes[reference.index]? == some (reference.address, reference.value)

theorem exactNormalizedWriteChecked_found
    (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference)
    (checked : exactNormalizedWriteChecked writes reference = true) :
    writes[reference.index]? = some (reference.address, reference.value) := by
  simpa [exactNormalizedWriteChecked] using checked

theorem exactNormalizedWriteChecked_member
    (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference)
    (checked : exactNormalizedWriteChecked writes reference = true) :
    (reference.address, reference.value) ∈ writes := by
  exact List.mem_iff_getElem?.mpr
    ⟨reference.index, exactNormalizedWriteChecked_found writes reference checked⟩

/-- The only stack bases accepted by the initial PE32 profile. -/
inductive OriginalStackAddressBase where
  | esp
  | ebp
deriving Repr, DecidableEq

def OriginalStackAddressBase.reg : OriginalStackAddressBase -> Reg
  | .esp => .esp
  | .ebp => .ebp

/-- Exact source syntax for a canonical affine offset.  Keeping addition and
subtraction distinct binds the certificate to the normalized expression rather
than merely to an equivalent concrete value. -/
inductive OriginalAffineOffset where
  | zero
  | add (value : Nat)
  | sub (value : Nat)
deriving Repr, DecidableEq

def OriginalAffineOffset.checked : OriginalAffineOffset -> Bool
  | .zero => true
  | .add value | .sub value => value < 2 ^ 32

def OriginalAffineOffset.expression (base : Expr) :
    OriginalAffineOffset -> Expr
  | .zero => base
  | .add value => .add base (.constant value)
  | .sub value => .sub base (.constant value)

/-- A deterministic world-range reference.  The ID check prevents an index
from silently changing meaning if an untrusted producer reorders ranges. -/
structure OriginalRuntimeRangeReference where
  kind : OriginalRuntimeRangeKind
  index : Nat
  id : Nat
deriving Repr, DecidableEq

def OriginalRuntimeRangeReference.resolve?
    (world : RelationalWorld) (reference : OriginalRuntimeRangeReference) :
    Option DynamicAddressRangePair :=
  match reference.kind with
  | .stack => world.stackRanges[reference.index]?
  | .dynamic => world.dynamicRanges[reference.index]?

def OriginalRuntimeRangeReference.checked
    (world : RelationalWorld) (reference : OriginalRuntimeRangeReference) : Bool :=
  match reference.resolve? world with
  | none => false
  | some range => range.id == reference.id

theorem OriginalRuntimeRangeReference.resolve_member
    (world : RelationalWorld) (reference : OriginalRuntimeRangeReference)
    (range : DynamicAddressRangePair)
    (found : reference.resolve? world = some range) :
    match reference.kind with
    | .stack => range ∈ world.stackRanges
    | .dynamic => range ∈ world.dynamicRanges := by
  cases kindExact : reference.kind with
  | stack =>
      simp only [OriginalRuntimeRangeReference.resolve?, kindExact] at found
      exact List.mem_iff_getElem?.mpr ⟨reference.index, found⟩
  | dynamic =>
      simp only [OriginalRuntimeRangeReference.resolve?, kindExact] at found
      exact List.mem_iff_getElem?.mpr ⟨reference.index, found⟩

/-- Exact normalized address forms accepted for runtime writes.  A dynamic
base includes a checked offset within the selected dynamic range; this is the
one-sided form of a checked dynamic value-origin witness. -/
inductive OriginalRuntimeAddressCertificate where
  | stackAffine
      (base : OriginalStackAddressBase)
      (offset : OriginalAffineOffset)
      (range : OriginalRuntimeRangeReference)
  | dynamicAffine
      (base : Expr)
      (baseOffset : Nat)
      (offset : OriginalAffineOffset)
      (range : OriginalRuntimeRangeReference)
deriving Repr, DecidableEq

def OriginalRuntimeAddressCertificate.rangeReference :
    OriginalRuntimeAddressCertificate -> OriginalRuntimeRangeReference
  | .stackAffine _ _ range => range
  | .dynamicAffine _ _ _ range => range

def OriginalRuntimeAddressCertificate.expectedAddress :
    OriginalRuntimeAddressCertificate -> Expr
  | .stackAffine base offset _ =>
      offset.expression (.inputReg base.reg)
  | .dynamicAffine base _ offset _ => offset.expression base

/-- Exact reflective check for one normalized runtime write.  Ordinary
normalized writes are four bytes; x87 and bulk effects use their separate
variable-width checked footprint interfaces. -/
def originalNormalizedRuntimeWriteChecked
    (world : RelationalWorld) (state : MachineState)
    (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference)
    (certificate : OriginalRuntimeAddressCertificate) : Bool :=
  exactNormalizedWriteChecked writes reference &&
    match certificate.rangeReference.resolve? world with
    | none => false
    | some range =>
        (range.id == certificate.rangeReference.id) &&
          ((match certificate with
            | .stackAffine base offset rangeReference =>
                rangeReference.kind == .stack && offset.checked &&
                  reference.address ==
                    offset.expression (.inputReg base.reg)
            | .dynamicAffine base baseOffset offset rangeReference =>
                rangeReference.kind == .dynamic && offset.checked &&
                  reference.address == offset.expression base &&
                  baseOffset < range.size &&
                  base.eval state ==
                    range.originalBase + BitVec.ofNat 32 baseOffset) &&
            ((range.originalBase.toNat <=
                (reference.address.eval state).toNat) &&
              ((reference.address.eval state).toNat + 4 <=
                range.originalBase.toNat + range.size)))

def originalNormalizedRuntimeWriteChecked_toWitness
    (world : RelationalWorld) (state : MachineState)
    (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference)
    (certificate : OriginalRuntimeAddressCertificate)
    (checked : originalNormalizedRuntimeWriteChecked world state writes
      reference certificate = true) :
    OriginalRuntimeAccessWitness world (reference.address.eval state) 4 := by
  simp only [originalNormalizedRuntimeWriteChecked, Bool.and_eq_true] at checked
  have exactWrite := checked.1
  cases found : certificate.rangeReference.resolve? world with
  | none => simp [found] at checked
  | some range =>
      have rest := checked.2
      simp only [found, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at rest
      refine {
        range
        kind := certificate.rangeReference.kind
        rangeMember := certificate.rangeReference.resolve_member world range found
        bytesPositive := by omega
        startsInside := rest.2.2.1
        endsInside := rest.2.2.2
      }

theorem originalNormalizedRuntimeWriteChecked_sound
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference)
    (certificate : OriginalRuntimeAddressCertificate)
    (checked : originalNormalizedRuntimeWriteChecked world state writes
      reference certificate = true)
    (partition : HoldsIn context world) :
    OriginalByteSpanValid (reference.address.eval state) 4 ∧
      ∀ wordAddress,
        writableStaticWordInPe context.originalPe wordAddress = true →
          OriginalAccessAvoidsWord wordAddress
            (reference.address.eval state) 4 := by
  let witness := originalNormalizedRuntimeWriteChecked_toWitness world state
    writes reference certificate checked
  exact ⟨witness.spanValid partition, fun wordAddress wordValid =>
    witness.avoidsWritableStaticWord partition wordValid⟩

/-- A generated provider stores the checked Boolean once and downstream
preservation consumes the resulting opaque witness. -/
structure CheckedOriginalNormalizedRuntimeWrite
    (world : RelationalWorld) (state : MachineState)
    (writes : List (Expr × Expr)) where
  reference : OriginalNormalizedWriteReference
  certificate : OriginalRuntimeAddressCertificate
  checked : originalNormalizedRuntimeWriteChecked world state writes reference
    certificate = true

def CheckedOriginalNormalizedRuntimeWrite.access
    {world : RelationalWorld} {state : MachineState}
    {writes : List (Expr × Expr)}
  (checked : CheckedOriginalNormalizedRuntimeWrite world state writes) :
    OriginalRuntimeAccessWitness world
      (checked.reference.address.eval state) 4 :=
  originalNormalizedRuntimeWriteChecked_toWitness world state writes
    checked.reference checked.certificate checked.checked

theorem CheckedOriginalNormalizedRuntimeWrite.exactWrite
    {world : RelationalWorld} {state : MachineState}
    {writes : List (Expr × Expr)}
    (checked : CheckedOriginalNormalizedRuntimeWrite world state writes) :
    (checked.reference.address, checked.reference.value) ∈ writes := by
  apply exactNormalizedWriteChecked_member writes checked.reference
  have all := checked.checked
  simp only [originalNormalizedRuntimeWriteChecked, Bool.and_eq_true] at all
  exact all.1

theorem CheckedOriginalNormalizedRuntimeWrite.avoidsWritableStaticWord
    {context : StaticProofContext} {world : RelationalWorld}
    {state : MachineState} {writes : List (Expr × Expr)}
    (checked : CheckedOriginalNormalizedRuntimeWrite world state writes)
    (partition : HoldsIn context world) (wordAddress : Word)
    (wordValid : writableStaticWordInPe context.originalPe wordAddress = true) :
    OriginalAccessAvoidsWord wordAddress
      (checked.reference.address.eval state) 4 :=
  checked.access.avoidsWritableStaticWord partition wordValid

/-- Exact static-slot binding.  This check does not claim disjointness: a
static write can overlap protected state and must use an explicit related
post-update proof. -/
def originalNormalizedStaticWriteChecked
    (context : StaticProofContext) (state : MachineState)
    (writes : List (Expr × Expr))
    (reference : OriginalNormalizedWriteReference)
    (requirement : OriginalStaticWordRequirement) : Bool :=
  exactNormalizedWriteChecked writes reference &&
    reference.address.eval state == requirement.slot.originalAddress &&
    writableStaticWordInPe context.originalPe
      requirement.slot.originalAddress

structure CheckedOriginalNormalizedStaticRelatedWrite
    (context : StaticProofContext) (state : MachineState)
    (writes : List (Expr × Expr)) (afterWorld : RelationalWorld)
    (afterMemory : Memory) where
  reference : OriginalNormalizedWriteReference
  requirement : OriginalStaticWordRequirement
  checked : originalNormalizedStaticWriteChecked context state writes reference
    requirement = true
  relatedUpdate : requirement.Holds context afterWorld afterMemory

theorem CheckedOriginalNormalizedStaticRelatedWrite.exactWrite
    {context : StaticProofContext} {state : MachineState}
    {writes : List (Expr × Expr)} {afterWorld : RelationalWorld}
    {afterMemory : Memory}
    (checked : CheckedOriginalNormalizedStaticRelatedWrite context state writes
      afterWorld afterMemory) :
    (checked.reference.address, checked.reference.value) ∈ writes := by
  apply exactNormalizedWriteChecked_member writes checked.reference
  have all := checked.checked
  simp only [originalNormalizedStaticWriteChecked, Bool.and_eq_true] at all
  exact all.1.1

theorem CheckedOriginalNormalizedStaticRelatedWrite.addressExact
    {context : StaticProofContext} {state : MachineState}
    {writes : List (Expr × Expr)} {afterWorld : RelationalWorld}
    {afterMemory : Memory}
    (checked : CheckedOriginalNormalizedStaticRelatedWrite context state writes
      afterWorld afterMemory) :
    checked.reference.address.eval state =
      checked.requirement.slot.originalAddress := by
  have all := checked.checked
  simp only [originalNormalizedStaticWriteChecked, Bool.and_eq_true,
    beq_iff_eq] at all
  exact all.1.2

def noNormalizedWritesChecked (writes : List (Expr × Expr)) : Bool :=
  writes.isEmpty

theorem noNormalizedWritesChecked_sound (writes : List (Expr × Expr))
    (checked : noNormalizedWritesChecked writes = true) : writes = [] := by
  simpa [noNormalizedWritesChecked, List.isEmpty_iff] using checked

#print axioms exactNormalizedWriteChecked_member
#print axioms originalNormalizedRuntimeWriteChecked_toWitness
#print axioms originalNormalizedRuntimeWriteChecked_sound
#print axioms CheckedOriginalNormalizedRuntimeWrite.exactWrite
#print axioms CheckedOriginalNormalizedRuntimeWrite.avoidsWritableStaticWord
#print axioms CheckedOriginalNormalizedStaticRelatedWrite.exactWrite
#print axioms CheckedOriginalNormalizedStaticRelatedWrite.addressExact
#print axioms noNormalizedWritesChecked_sound

end StageA.Relational.OriginalRuntimeMemoryAccessChecker
