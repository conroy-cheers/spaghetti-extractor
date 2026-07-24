import StageA.RelationalFiniteIndex
import StageA.RelationalInterpreter
import StageA.RelationalPEBytePacks

namespace StageA.Relational.InterpreterKernelData

open StageA.Formal
open StageA.Relational.Interpreter
open StageA.Relational.PEBytePacks

/-! The PE32 layout consumed by the fixed Stage B interpreter.  These
definitions parse candidate bytes; generated manifests and linker maps only
propose the two table RVAs and the expected semantic records. -/

def transferRecordSize : Nat := 40
def wordNodeSize : Nat := 36
def x87NodeSize : Nat := 36
def actionSize : Nat := 32
def callSize : Nat := 64
def stackInputSize : Nat := 12
def x87ReplaySize : Nat := 44

def maxWordNodes : Nat := 1024
def maxX87Nodes : Nat := 256
def maxActions : Nat := 8192
def maxCalls : Nat := 1024
def maxCallArguments : Nat := 64
def maxX87Replays : Nat := 1024
def maxCStringBytes : Nat := 512

/-- Read one exact non-writable mapped-image span.  This intentionally lives
in the data kernel so table proofs do not depend on executable-kernel proofs. -/
def immutableMappedBytes (pe : PE32) (span : Span) : Option Bytes :=
  match pe.sections.filter fun sec =>
      !sec.writable && sec.virtualAddress <= span.start &&
        span.stop <= sec.virtualAddress + sec.mappedSize with
  | [sec] => do
      let offset := span.start - sec.virtualAddress
      if offset + span.size > sec.mappedSize then none else
      let rawCount :=
        if offset < sec.rawSize then min span.size (sec.rawSize - offset)
        else 0
      let raw <- pe.bytes.readBytes (sec.rawPointer + offset) rawCount
      pure (raw ++ List.replicate (span.size - rawCount) 0)
  | _ => none

def lookupProgramRecord (records : List ProgramRecord)
    (sourceRva : Nat) : Option ProgramRecord :=
  records.find? (fun record => record.sourceRva == sourceRva)

/-- Linear certificate checker for the source-RVA order emitted by the table.
Using `List.Nodup`'s decision procedure directly is quadratic and needlessly
revisits opaque semantic records in the final bundle. -/
def strictlyIncreasing : List Nat -> Bool
  | [] | [_] => true
  | head :: next :: tail =>
      decide (head < next) && strictlyIncreasing (next :: tail)

theorem strictlyIncreasing_head_lt
    {head : Nat} {tail : List Nat}
    (checked : strictlyIncreasing (head :: tail) = true) :
    forall value, value ∈ tail -> head < value := by
  induction tail generalizing head with
  | nil => simp
  | cons next tail induction =>
      simp only [strictlyIncreasing, Bool.and_eq_true] at checked
      intro value member
      simp only [List.mem_cons] at member
      rcases member with rfl | member
      · exact of_decide_eq_true checked.1
      · exact Nat.lt_trans (of_decide_eq_true checked.1)
          (induction checked.2 value member)

theorem strictlyIncreasing_nodup
    {values : List Nat} (checked : strictlyIncreasing values = true) :
    values.Nodup := by
  induction values with
  | nil => exact List.nodup_nil
  | cons head tail induction =>
      apply List.nodup_cons.mpr
      constructor
      · intro member
        exact (Nat.lt_irrefl head)
          (strictlyIncreasing_head_lt checked head member)
      · cases tail with
        | nil => exact List.nodup_nil
        | cons next tail =>
            simp only [strictlyIncreasing, Bool.and_eq_true] at checked
            exact induction checked.2

structure RawX87Replay where
  imageBase : Nat
  rvaStart : Nat
  rvaEnd : Nat
  instructionCount : Nat
  instructionBytes : Bytes
  instructionBytesSha256 : String
  transferInstructionBytesSha256 : String
  contractSha256 : String
  checkedDecoder : String
  checkedExecutor : String
deriving Repr, DecidableEq

structure CompiledProgramRecord where
  record : ProgramRecord
  x87Replays : List RawX87Replay
deriving Repr, DecidableEq

/-- The fixed-width part of one compiled transfer.  Separating this 40-byte
decode from the pointed-to arrays gives generated proofs a small PE-backed
cache boundary before any semantic values are assembled. -/
structure TransferDescriptor where
  sourceRva : Nat
  wordCount : Nat
  x87Count : Nat
  actionCount : Nat
  replayCount : Nat
  wordPointer : Nat
  x87Pointer : Nat
  actionPointer : Nat
  callPointer : Nat
  replayPointer : Nat
deriving Repr, DecidableEq

structure LayoutTrace where
  relocatedPointerFields : List Nat := []
  zeroPointerFields : List Nat := []
deriving Repr, DecidableEq

/-- Reflective expected data for one compiled transfer.  Generated modules put
small contiguous arrays of these values behind one checked `FiniteIndex` leaf;
the values become authoritative only through the PE-backed checks below. -/
structure TransferCertificateData where
  descriptor : TransferDescriptor
  wordNodes : List RawWordNode
  x87Nodes : List RawWordNode
  actions : List RawAction
  calls : List RawCall
  x87Replays : List RawX87Replay
  wordTrace : LayoutTrace
  x87Trace : LayoutTrace
  actionTrace : LayoutTrace
  callTrace : LayoutTrace
  replayTrace : LayoutTrace
deriving Repr, DecidableEq

def TransferCertificateData.compiled (data : TransferCertificateData) :
    CompiledProgramRecord := {
  record := {
    sourceRva := data.descriptor.sourceRva
    wordNodes := data.wordNodes
    x87Nodes := data.x87Nodes
    calls := data.calls
    actions := data.actions
  }
  x87Replays := data.x87Replays
}

structure TransferCertificatePack where
  startIndex : Nat
  entries : FiniteIndex TransferCertificateData
deriving Repr, DecidableEq

/-- The small reflective check shared by every generated certificate pack.
Semantic component proofs remain independent, while this certificate prevents
the generated array boundary itself from silently dropping, duplicating, or
oversizing entries. -/
def TransferCertificatePack.indexChecked (pack : TransferCertificatePack)
    (expectedStart expectedCount leafCapacity : Nat) : Bool :=
  decide (pack.startIndex = expectedStart) &&
    (decide (pack.entries.toList.length = expectedCount) &&
      pack.entries.structurallyValid leafCapacity)

structure TransferCertificatePack.IndexCertificate
    (pack : TransferCertificatePack)
    (expectedStart expectedCount leafCapacity : Nat) : Prop where
  checked : pack.indexChecked expectedStart expectedCount leafCapacity = true

def TransferCertificatePack.IndexCertificate.of_checked
    (pack : TransferCertificatePack)
    (expectedStart expectedCount leafCapacity : Nat)
    (checked : pack.indexChecked expectedStart expectedCount leafCapacity = true) :
    TransferCertificatePack.IndexCertificate
      pack expectedStart expectedCount leafCapacity := { checked }

theorem TransferCertificatePack.IndexCertificate.exact
    {pack : TransferCertificatePack}
    {expectedStart expectedCount leafCapacity : Nat}
    (certificate : TransferCertificatePack.IndexCertificate pack
      expectedStart expectedCount leafCapacity) :
    pack.startIndex = expectedStart ∧
      pack.entries.toList.length = expectedCount ∧
      pack.entries.structurallyValid leafCapacity = true := by
  have checked := certificate.checked
  simp only [TransferCertificatePack.indexChecked, Bool.and_eq_true] at checked
  exact ⟨of_decide_eq_true checked.1,
    of_decide_eq_true checked.2.1, checked.2.2⟩

/-- The only PE metadata consulted while decoding the fixed semantic-record
layout.  Keeping this view independent of `PE32.bytes` lets local generated
certificates normalize without importing or reducing the complete candidate
image.  The global binding certificate later proves that this view is exactly
the projection of the parsed PE. -/
structure CandidateDataLayout where
  imageBase : Nat
  sizeOfImage : Nat
  sections : List Section
deriving Repr, DecidableEq

def CandidateDataLayout.ofPE (pe : PE32) : CandidateDataLayout := {
  imageBase := pe.imageBase
  sizeOfImage := pe.sizeOfImage
  sections := pe.sections
}

def CandidateDataLayout.absoluteImageVaToRva
    (layout : CandidateDataLayout) (absolute : Nat) : Option Nat :=
  if layout.imageBase <= absolute &&
      absolute < layout.imageBase + layout.sizeOfImage then
    some (absolute - layout.imageBase)
  else
    none

/-- A byte-free PE value used only to reuse the reviewed record decoder in
local proof leaves.  The decoder is proved below to observe exactly these
three fields and no other PE metadata. -/
def CandidateDataLayout.asPE (layout : CandidateDataLayout) : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := layout.imageBase
  sectionAlignment := 0
  fileAlignment := 0
  sizeOfImage := layout.sizeOfImage
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := layout.sections
}

def LayoutTrace.append (left right : LayoutTrace) : LayoutTrace := {
  relocatedPointerFields :=
    left.relocatedPointerFields ++ right.relocatedPointerFields
  zeroPointerFields := left.zeroPointerFields ++ right.zeroPointerFields
}

def TransferCertificateData.trace (data : TransferCertificateData) : LayoutTrace :=
  data.wordTrace.append (data.x87Trace.append
    (data.actionTrace.append (data.callTrace.append data.replayTrace)))

def transferCertificateDataListTrace : List TransferCertificateData -> LayoutTrace
  | [] => {}
  | head :: tail => head.trace.append (transferCertificateDataListTrace tail)

def LayoutTrace.localFieldsValid (trace : LayoutTrace) : Bool :=
  trace.relocatedPointerFields.all (fun field => field % 4 == 0) &&
    (trace.zeroPointerFields.all (fun field => field % 4 == 0) &&
      decide (trace.relocatedPointerFields ++ trace.zeroPointerFields).Nodup)

inductive LayoutM (alpha : Type) where
  | fail
  | ok (value : alpha) (trace : LayoutTrace := {})
deriving Repr, DecidableEq

protected def LayoutM.pure (value : alpha) : LayoutM alpha := .ok value

protected def LayoutM.bind (value : LayoutM alpha)
    (next : alpha -> LayoutM beta) : LayoutM beta :=
  match value with
  | .fail => .fail
  | .ok prior priorTrace =>
      match next prior with
      | .fail => .fail
      | .ok result resultTrace => .ok result (priorTrace.append resultTrace)

instance : Monad LayoutM where
  pure := LayoutM.pure
  bind := LayoutM.bind

@[simp] theorem LayoutM.monad_pure (value : alpha) :
    (pure value : LayoutM alpha) = .ok value {} := rfl

@[simp] theorem LayoutM.fail_bind (next : alpha -> LayoutM beta) :
    (LayoutM.fail >>= next) = LayoutM.fail := rfl

@[simp] theorem LayoutM.ok_bind (value : alpha) (trace : LayoutTrace)
    (next : alpha -> LayoutM beta) :
    (LayoutM.ok value trace >>= next) =
      match next value with
      | .fail => .fail
      | .ok result resultTrace => .ok result (trace.append resultTrace) := rfl

def LayoutM.ofOption : Option alpha -> LayoutM alpha
  | none => .fail
  | some value => pure value

def LayoutM.guard (condition : Bool) : LayoutM Unit :=
  if condition then pure () else .fail

def LayoutM.value? : LayoutM alpha -> Option alpha
  | .fail => none
  | .ok value _ => some value

def LayoutM.trace? : LayoutM alpha -> Option LayoutTrace
  | .fail => none
  | .ok _ trace => some trace

def immutableRvaBytes (pe : PE32) (imports : List PEImport)
    (rva size : Nat) : Option Bytes := do
  if size == 0 || rva + size > pe.sizeOfImage ||
      !imageRangeExcludesIat imports rva size then none else
  immutableMappedBytes pe { start := rva, size := size }

/-- One locally materialized immutable RVA span.  Generated values are not
trusted: `ImmutableByteCache.authoritative` binds every entry back to an exact
read from the parsed PE. -/
structure ImmutableByteRange where
  rva : Nat
  size : Nat
  bytes : Bytes
deriving Repr, DecidableEq

/-- A finite local read cache.  Its fallback is explicit: local certificates
quantify over every fallback, while the global binder instantiates it with the
authoritative PE reader and proves that every cached range agrees with it. -/
structure LocalImmutableByteCache where
  ranges : FiniteIndex ImmutableByteRange
deriving Repr, DecidableEq

def LocalImmutableByteCache.readWith (cache : LocalImmutableByteCache)
    (fallback : Nat -> Nat -> Option Bytes) (rva size : Nat) : Option Bytes :=
  match cache.ranges.toList.find? (fun range =>
      range.rva == rva && range.size == size) with
  | some range => some range.bytes
  | none => fallback rva size

theorem LocalImmutableByteCache.readWith_eq_fallback
    (cache : LocalImmutableByteCache)
    (fallback : Nat -> Nat -> Option Bytes)
    (authoritative : forall range, range ∈ cache.ranges.toList ->
      fallback range.rva range.size = some range.bytes) :
    cache.readWith fallback = fallback := by
  funext rva size
  unfold LocalImmutableByteCache.readWith
  split
  next range found =>
    have matched := List.find?_some found
    have member := List.mem_of_find?_eq_some found
    simp only [Bool.and_eq_true, beq_iff_eq] at matched
    symm
    simpa [matched.1, matched.2] using authoritative range member
  next => rfl

/-- A small cache layered over the authoritative PE reader.  A missing entry
falls back to the PE, so replacing the reader by this cache is semantics
preserving; generated checks remain cheap only when they supplied every span
that the decoder actually uses. -/
structure ImmutableByteCache (pe : PE32) (imports : List PEImport) where
  ranges : FiniteIndex ImmutableByteRange
  authoritative : forall range, range ∈ ranges.toList ->
    immutableRvaBytes pe imports range.rva range.size = some range.bytes

def ImmutableByteCache.read (cache : ImmutableByteCache pe imports)
    (rva size : Nat) : Option Bytes :=
  match cache.ranges.toList.find? (fun range =>
      range.rva == rva && range.size == size) with
  | some range => some range.bytes
  | none => immutableRvaBytes pe imports rva size

theorem ImmutableByteCache.read_eq_authoritative
    (cache : ImmutableByteCache pe imports) :
    cache.read = immutableRvaBytes pe imports := by
  funext rva size
  unfold ImmutableByteCache.read
  split
  next range found =>
    have matched := List.find?_some found
    have member := List.mem_of_find?_eq_some found
    simp only [Bool.and_eq_true, beq_iff_eq] at matched
    symm
    simpa [matched.1, matched.2] using cache.authoritative range member
  next => rfl

/-- Bridge an immutable PE read to adjacent, independently checked raw-byte
pack slices.  The arithmetic premises contain metadata only; `slicesRead`
reduces only the referenced local packs. -/
theorem immutableRvaBytes_eq_slices
    (pe : PE32) (imports : List PEImport) (sec : Section)
    (rva size rawCount : Nat) (slices : List (PEBytePackSlice pe))
    (rawBytes expected : Bytes)
    (accepted :
      (size == 0 || rva + size > pe.sizeOfImage ||
        !imageRangeExcludesIat imports rva size) = false)
    (sectionExact : pe.sections.filter (fun candidate =>
      !candidate.writable && candidate.virtualAddress <= rva &&
        ({ start := rva, size := size } : Span).stop <=
          candidate.virtualAddress + candidate.mappedSize) = [sec])
    (mappedFits : rva - sec.virtualAddress + size <= sec.mappedSize)
    (rawCountExact :
      (if rva - sec.virtualAddress < sec.rawSize then
        min size (sec.rawSize - (rva - sec.virtualAddress)) else 0) = rawCount)
    (chain : PEBytePackSliceChain pe
      (sec.rawPointer + (rva - sec.virtualAddress)) rawCount slices)
    (slicesRead : readPEBytePackSlices slices = some rawBytes)
    (expectedExact :
      rawBytes ++ List.replicate (size - rawCount) 0 = expected) :
    immutableRvaBytes pe imports rva size = some expected := by
  unfold immutableRvaBytes immutableMappedBytes
  rw [accepted]
  simp only [Bool.false_eq_true, ↓reduceIte]
  rw [sectionExact]
  simp only
  rw [if_neg (by omega)]
  rw [rawCountExact, chain.readBytes_eq, slicesRead]
  simp [expectedExact]

/-- A compact, nondependent reference to one exact candidate-byte pack.  The
global authority emits arrays of these plans rather than tens of thousands of
near-identical proof terms. -/
structure RawByteSlicePlan where
  packIndex : Nat
  offset : Nat
  size : Nat
deriving Repr, DecidableEq

def readRawByteSlicePlans {pe : PE32}
    (catalog : FiniteIndex (PEBytePackCertificate pe)) :
    List RawByteSlicePlan -> Option Bytes
  | [] => some []
  | plan :: plans => do
      let pack <- catalog.get? plan.packIndex
      if plan.size == 0 || plan.offset + plan.size > pack.pack.length then none else
      let head <- pack.pack.readBytes plan.offset plan.size
      let tail <- readRawByteSlicePlans catalog plans
      pure (head ++ tail)

def rawByteSlicePlansChecked {pe : PE32}
    (catalog : FiniteIndex (PEBytePackCertificate pe)) :
    Nat -> Nat -> List RawByteSlicePlan -> Bool
  | _, remaining, [] => remaining == 0
  | rawOffset, remaining, plan :: plans =>
      match catalog.get? plan.packIndex with
      | none => false
      | some pack =>
          plan.size != 0 && plan.size <= remaining &&
            (plan.offset + plan.size <= pack.pack.length &&
              (pack.rawOffset + plan.offset == rawOffset &&
                rawByteSlicePlansChecked catalog
                  (rawOffset + plan.size) (remaining - plan.size) plans))

inductive RawByteSlicePlansCertificate {pe : PE32}
    (catalog : FiniteIndex (PEBytePackCertificate pe)) :
    Nat -> Nat -> List RawByteSlicePlan -> Prop where
  | nil (rawOffset : Nat) :
      RawByteSlicePlansCertificate catalog rawOffset 0 []
  | cons (plan : RawByteSlicePlan) (plans : List RawByteSlicePlan)
      (pack : PEBytePackCertificate pe)
      (found : catalog.get? plan.packIndex = some pack)
      (nonempty : 0 < plan.size)
      (bounded : plan.offset + plan.size <= pack.pack.length)
      (starts : pack.rawOffset + plan.offset = rawOffset)
      (tail : RawByteSlicePlansCertificate catalog
        (rawOffset + plan.size) tailSize plans) :
      RawByteSlicePlansCertificate catalog rawOffset
        (plan.size + tailSize) (plan :: plans)

def RawByteSlicePlansCertificate.of_checked {pe : PE32}
    (catalog : FiniteIndex (PEBytePackCertificate pe))
    (rawOffset size : Nat) (plans : List RawByteSlicePlan)
    (checked : rawByteSlicePlansChecked catalog rawOffset size plans = true) :
    RawByteSlicePlansCertificate catalog rawOffset size plans := by
  induction plans generalizing rawOffset size with
  | nil =>
      simp only [rawByteSlicePlansChecked, beq_iff_eq] at checked
      subst size
      exact .nil rawOffset
  | cons plan plans induction =>
      simp only [rawByteSlicePlansChecked] at checked
      split at checked
      next => contradiction
      next pack found =>
        simp only [Bool.and_eq_true, bne_iff_ne, decide_eq_true_eq,
          beq_iff_eq] at checked
        have nonzero := checked.1.1
        have sizeBounded := checked.1.2
        have packBounded := checked.2.1
        have starts := checked.2.2.1
        have tailChecked := checked.2.2.2
        have tail := induction (rawOffset := rawOffset + plan.size)
          (size := size - plan.size) tailChecked
        rw [show size = plan.size + (size - plan.size) by omega]
        exact .cons plan plans pack found (Nat.pos_of_ne_zero nonzero)
          packBounded starts tail

theorem RawByteSlicePlansCertificate.readBytes_eq {pe : PE32}
    {catalog : FiniteIndex (PEBytePackCertificate pe)}
    {rawOffset size : Nat} {plans : List RawByteSlicePlan}
    (certificate : RawByteSlicePlansCertificate catalog rawOffset size plans) :
    pe.bytes.readBytes rawOffset size =
      readRawByteSlicePlans catalog plans := by
  induction certificate with
  | nil => simp [ByteTree.readBytes, readRawByteSlicePlans]
  | @cons rawOffset tailSize plan plans pack found nonempty bounded starts tail ih =>
      rw [ByteTree.readBytes_add]
      simp [readRawByteSlicePlans, found, Nat.ne_of_gt nonempty,
        Nat.not_lt_of_ge bounded]
      rw [<- starts]
      rw [pack.readBytes_eq plan.offset plan.size bounded]
      rw [starts, ih]

structure ImmutableRangeBindingPlan where
  sectionIndex : Nat
  rawOffset : Nat
  rawCount : Nat
  slices : List RawByteSlicePlan
deriving Repr, DecidableEq

def immutableRangeBindingChecked {pe : PE32}
    (layout : CandidateDataLayout) (imports : List PEImport)
    (catalog : FiniteIndex (PEBytePackCertificate pe))
    (range : ImmutableByteRange) (plan : ImmutableRangeBindingPlan) : Bool :=
  match layout.sections[plan.sectionIndex]? with
  | none => false
  | some sec =>
      let accepted :=
        (range.size == 0 || range.rva + range.size > layout.sizeOfImage ||
          !imageRangeExcludesIat imports range.rva range.size) == false
      let sectionExact := layout.sections.filter (fun candidate =>
        !candidate.writable && candidate.virtualAddress <= range.rva &&
          range.rva + range.size <=
            candidate.virtualAddress + candidate.mappedSize) == [sec]
      let offset := range.rva - sec.virtualAddress
      let rawCount :=
        if offset < sec.rawSize then min range.size (sec.rawSize - offset) else 0
      accepted && sectionExact && offset + range.size <= sec.mappedSize &&
        (plan.rawOffset == sec.rawPointer + offset &&
          (plan.rawCount == rawCount &&
            (rawByteSlicePlansChecked catalog plan.rawOffset plan.rawCount
              plan.slices &&
              match readRawByteSlicePlans catalog plan.slices with
              | none => false
              | some rawBytes =>
                  rawBytes ++ List.replicate (range.size - plan.rawCount) 0 ==
                    range.bytes)))

structure ImmutableRangeBindingCertificate {pe : PE32}
    (layout : CandidateDataLayout) (imports : List PEImport)
    (catalog : FiniteIndex (PEBytePackCertificate pe))
    (range : ImmutableByteRange) (plan : ImmutableRangeBindingPlan) where
  mappedSection : Section
  sectionFound : layout.sections[plan.sectionIndex]? = some mappedSection
  accepted :
    (range.size == 0 || range.rva + range.size > layout.sizeOfImage ||
      !imageRangeExcludesIat imports range.rva range.size) = false
  sectionExact : layout.sections.filter (fun candidate =>
    !candidate.writable && candidate.virtualAddress <= range.rva &&
      range.rva + range.size <=
        candidate.virtualAddress + candidate.mappedSize) = [mappedSection]
  mappedFits : range.rva - mappedSection.virtualAddress + range.size <=
    mappedSection.mappedSize
  rawOffsetExact :
    plan.rawOffset = mappedSection.rawPointer +
      (range.rva - mappedSection.virtualAddress)
  rawCountExact :
    plan.rawCount =
      (if range.rva - mappedSection.virtualAddress < mappedSection.rawSize then
        min range.size
          (mappedSection.rawSize - (range.rva - mappedSection.virtualAddress))
      else 0)
  slices : RawByteSlicePlansCertificate catalog
    plan.rawOffset plan.rawCount plan.slices
  rawBytes : Bytes
  slicesRead : readRawByteSlicePlans catalog plan.slices = some rawBytes
  expectedExact :
    rawBytes ++ List.replicate (range.size - plan.rawCount) 0 = range.bytes

noncomputable def ImmutableRangeBindingCertificate.of_checked {pe : PE32}
    (layout : CandidateDataLayout) (imports : List PEImport)
    (catalog : FiniteIndex (PEBytePackCertificate pe))
    (range : ImmutableByteRange) (plan : ImmutableRangeBindingPlan)
    (checked : immutableRangeBindingChecked layout imports catalog range plan = true) :
    ImmutableRangeBindingCertificate layout imports catalog range plan := by
  unfold immutableRangeBindingChecked at checked
  split at checked
  next => contradiction
  next mappedSection sectionFound =>
    simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at checked
    rcases checked with
      ⟨⟨⟨accepted, sectionExact⟩, mappedFits⟩, rawOffsetExact,
        rawCountExact, slicesChecked, bytesChecked⟩
    rcases slicesRead : readRawByteSlicePlans catalog plan.slices with _ | rawBytes
    · simp [slicesRead] at bytesChecked
    · refine {
        mappedSection
        sectionFound
        accepted
        sectionExact
        mappedFits
        rawOffsetExact
        rawCountExact
        slices := RawByteSlicePlansCertificate.of_checked catalog
          plan.rawOffset plan.rawCount plan.slices slicesChecked
        rawBytes
        slicesRead
        expectedExact := by simpa [slicesRead] using bytesChecked
      }

theorem ImmutableRangeBindingCertificate.exact {pe : PE32}
    {layout : CandidateDataLayout} {imports : List PEImport}
    {catalog : FiniteIndex (PEBytePackCertificate pe)}
    {range : ImmutableByteRange} {plan : ImmutableRangeBindingPlan}
    (certificate :
      ImmutableRangeBindingCertificate layout imports catalog range plan)
    (layoutExact : CandidateDataLayout.ofPE pe = layout) :
    immutableRvaBytes pe imports range.rva range.size = some range.bytes := by
  unfold immutableRvaBytes immutableMappedBytes
  have imageExact : pe.sizeOfImage = layout.sizeOfImage := by
    rw [<- layoutExact]
    rfl
  rw [imageExact, certificate.accepted]
  simp only [Bool.false_eq_true, ↓reduceIte]
  have sectionsExact : pe.sections = layout.sections := by
    rw [<- layoutExact]
    rfl
  have sectionExact : pe.sections.filter (fun candidate =>
      !candidate.writable && candidate.virtualAddress <= range.rva &&
        ({ start := range.rva, size := range.size } : Span).stop <=
          candidate.virtualAddress + candidate.mappedSize) =
      [certificate.mappedSection] := by
    rw [sectionsExact]
    simpa [Span.stop] using certificate.sectionExact
  rw [sectionExact]
  simp only
  rw [if_neg (Nat.not_lt_of_ge certificate.mappedFits)]
  rw [<- certificate.rawCountExact, <- certificate.rawOffsetExact]
  rw [certificate.slices.readBytes_eq, certificate.slicesRead]
  simp [certificate.expectedExact]

def immutableRangeBindingsChecked {pe : PE32}
    (layout : CandidateDataLayout) (imports : List PEImport)
    (catalog : FiniteIndex (PEBytePackCertificate pe)) :
    List ImmutableByteRange -> List ImmutableRangeBindingPlan -> Bool
  | [], [] => true
  | range :: ranges, plan :: plans =>
      immutableRangeBindingChecked layout imports catalog range plan &&
        immutableRangeBindingsChecked layout imports catalog ranges plans
  | _, _ => false

inductive ImmutableRangeBindingsCertificate {pe : PE32}
    (layout : CandidateDataLayout) (imports : List PEImport)
    (catalog : FiniteIndex (PEBytePackCertificate pe)) :
    List ImmutableByteRange -> List ImmutableRangeBindingPlan -> Type where
  | nil : ImmutableRangeBindingsCertificate layout imports catalog [] []
  | cons (head : ImmutableRangeBindingCertificate
      layout imports catalog range plan)
      (tail : ImmutableRangeBindingsCertificate
        layout imports catalog ranges plans) :
      ImmutableRangeBindingsCertificate layout imports catalog
        (range :: ranges) (plan :: plans)

noncomputable def ImmutableRangeBindingsCertificate.of_checked {pe : PE32}
    (layout : CandidateDataLayout) (imports : List PEImport)
    (catalog : FiniteIndex (PEBytePackCertificate pe))
    (ranges : List ImmutableByteRange) (plans : List ImmutableRangeBindingPlan)
    (checked : immutableRangeBindingsChecked layout imports catalog
      ranges plans = true) :
    ImmutableRangeBindingsCertificate layout imports catalog ranges plans := by
  induction ranges generalizing plans with
  | nil =>
      cases plans <;> simp [immutableRangeBindingsChecked] at checked
      exact .nil
  | cons range ranges induction =>
      cases plans with
      | nil => simp [immutableRangeBindingsChecked] at checked
      | cons plan plans =>
          rw [immutableRangeBindingsChecked, Bool.and_eq_true] at checked
          exact .cons
            (ImmutableRangeBindingCertificate.of_checked
              layout imports catalog range plan checked.1)
            (induction plans checked.2)

theorem ImmutableRangeBindingsCertificate.all_exact {pe : PE32}
    {layout : CandidateDataLayout} {imports : List PEImport}
    {catalog : FiniteIndex (PEBytePackCertificate pe)}
    {ranges : List ImmutableByteRange} {plans : List ImmutableRangeBindingPlan}
    (certificate :
      ImmutableRangeBindingsCertificate layout imports catalog ranges plans)
    (layoutExact : CandidateDataLayout.ofPE pe = layout) :
    forall range, range ∈ ranges ->
      immutableRvaBytes pe imports range.rva range.size = some range.bytes := by
  intro range member
  induction certificate with
  | nil => simp at member
  | @cons headRange headPlan tailRanges tailPlans head tail induction =>
      simp only [List.mem_cons] at member
      rcases member with rfl | member
      · exact head.exact layoutExact
      · exact induction member

def checkedArrayBytesFrom (readImmutable : Nat -> Nat -> Option Bytes)
    (rva count stride maximum alignment : Nat)
    (physicalDummy : Bool := true) : Option Bytes := do
  if count > maximum || stride == 0 || alignment == 0 || rva % alignment != 0 then
    none
  else
    let physicalCount := if physicalDummy && count == 0 then 1 else count
    if physicalCount > maximum + 1 || physicalCount * stride >= 2 ^ 32 then none else
    readImmutable rva (physicalCount * stride)

def checkedArrayBytes (pe : PE32) (imports : List PEImport)
    (rva count stride maximum alignment : Nat)
    (physicalDummy : Bool := true) : Option Bytes :=
  checkedArrayBytesFrom (immutableRvaBytes pe imports)
    rva count stride maximum alignment physicalDummy

def readArrayU32 (bytes : Bytes) (index : Nat) : Option Nat :=
  readU32 bytes (index * 4)

def readStructU32 (bytes : Bytes) (offset : Nat) : Option Nat :=
  readU32 bytes offset

def relocatedPointerRva (pe : PE32) (fieldRva value : Nat) : LayoutM Nat := do
  LayoutM.guard (fieldRva % 4 == 0 && value != 0)
  let target <- LayoutM.ofOption (absoluteImageVaToRva pe value)
  .ok target { relocatedPointerFields := [fieldRva] }

def optionalPointerRva (pe : PE32) (fieldRva value : Nat) : LayoutM (Option Nat) := do
  LayoutM.guard (fieldRva % 4 == 0)
  if value == 0 then
    .ok none { zeroPointerFields := [fieldRva] }
  else
    let target <- relocatedPointerRva pe fieldRva value
    pure (some target)

def decodeManyAux (decode : Nat -> LayoutM alpha) : Nat -> Nat -> LayoutM (List alpha)
  | _, 0 => pure []
  | index, count + 1 => do
      let head <- decode index
      let tail <- decodeManyAux decode (index + 1) count
      pure (head :: tail)

def decodeMany (count : Nat) (decode : Nat -> LayoutM alpha) : LayoutM (List alpha) :=
  decodeManyAux decode 0 count

/-- Decode fixed-stride data from the current list tail.  The previous array
decoders repeatedly indexed from the beginning of a `Bytes` list, making a
concrete array proof quadratic in its byte length.  Advancing the tail once per
element preserves the byte-level decoder while making reduction linear in the
local range. -/
def decodeOptionStride (decode : Bytes -> Option alpha) (stride : Nat) :
    Nat -> Bytes -> Option (List alpha)
  | 0, _ => some []
  | count + 1, bytes => do
      let head <- decode bytes
      let tail <- decodeOptionStride decode stride count (bytes.drop stride)
      pure (head :: tail)

/-- `LayoutM` variant of `decodeOptionStride`; the element index is retained
for pointer-field RVAs while each fixed-width header is decoded at offset zero
from the current byte tail. -/
def decodeLayoutStride (decode : Nat -> Bytes -> LayoutM alpha) (stride : Nat) :
    Nat -> Nat -> Bytes -> LayoutM (List alpha)
  | _, 0, _ => pure []
  | index, count + 1, bytes => do
      let head <- decode index bytes
      let tail <- decodeLayoutStride decode stride (index + 1) count
        (bytes.drop stride)
      pure (head :: tail)

def decodeNodeFrom (bytes : Bytes) (offset : Nat) : Option RawWordNode := do
  let op <- readStructU32 bytes offset
  let arity <- readStructU32 bytes (offset + 4)
  let aux <- readStructU32 bytes (offset + 8)
  let immediate <- readStructU32 bytes (offset + 12)
  if arity > 5 then none else
  let args <- (List.range 5).mapM fun index =>
    readStructU32 bytes (offset + 16 + index * 4)
  pure { op, arity, aux, immediate, args := args.take arity }

def decodeActionFrom (bytes : Bytes) (offset : Nat) : Option RawAction := do
  let op <- readStructU32 bytes offset
  let arity <- readStructU32 bytes (offset + 4)
  let aux <- readStructU32 bytes (offset + 8)
  if arity > 5 then none else
  let args <- (List.range 5).mapM fun index =>
    readStructU32 bytes (offset + 12 + index * 4)
  pure { op, arity, aux, args := args.take arity }

def decodeNodeArrayFrom (pe : PE32) (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer count size maximum : Nat) : LayoutM (List RawWordNode) := do
  let rva <- relocatedPointerRva pe fieldRva pointer
  let bytes <- LayoutM.ofOption
    (checkedArrayBytesFrom readImmutable rva count size maximum 4)
  let nodes <- LayoutM.ofOption <|
    decodeOptionStride (fun tail => decodeNodeFrom tail 0) size count bytes
  pure nodes

def decodeNodeArray (pe : PE32) (imports : List PEImport)
    (fieldRva pointer count size maximum : Nat) : LayoutM (List RawWordNode) :=
  decodeNodeArrayFrom pe (immutableRvaBytes pe imports)
    fieldRva pointer count size maximum

def decodeActionArrayFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer count : Nat) : LayoutM (List RawAction) := do
  LayoutM.guard (count != 0)
  let rva <- relocatedPointerRva pe fieldRva pointer
  let bytes <- LayoutM.ofOption
    (checkedArrayBytesFrom readImmutable rva count actionSize maxActions 4 false)
  let actions <- LayoutM.ofOption <|
    decodeOptionStride (fun tail => decodeActionFrom tail 0)
      actionSize count bytes
  pure actions

def decodeActionArray (pe : PE32) (imports : List PEImport)
    (fieldRva pointer count : Nat) : LayoutM (List RawAction) :=
  decodeActionArrayFrom pe (immutableRvaBytes pe imports) fieldRva pointer count

def decodeU32ArrayFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer count maximum : Nat) : LayoutM (List Nat) := do
  let rva <- relocatedPointerRva pe fieldRva pointer
  let bytes <- LayoutM.ofOption
    (checkedArrayBytesFrom readImmutable rva count 4 maximum 4)
  let values <- LayoutM.ofOption <|
    decodeOptionStride (fun tail => readU32 tail 0) 4 count bytes
  pure values

def decodeU32Array (pe : PE32) (imports : List PEImport)
    (fieldRva pointer count maximum : Nat) : LayoutM (List Nat) :=
  decodeU32ArrayFrom pe (immutableRvaBytes pe imports)
    fieldRva pointer count maximum

def takeAsciiCString : Bytes -> Option Bytes
  | [] => none
  | 0 :: _ => some []
  | byte :: tail => do
      if byte >= 128 then none else
      let rest <- takeAsciiCString tail
      pure (byte :: rest)

def readImmutableCStringFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (rva : Nat) : Option String := do
  let sec <- match pe.sections.filter fun candidate =>
      !candidate.writable && candidate.virtualAddress <= rva &&
        rva < candidate.virtualAddress + candidate.mappedSize with
    | [candidate] => some candidate
    | _ => none
  let available := min maxCStringBytes
    (sec.virtualAddress + sec.mappedSize - rva)
  let window <- readImmutable rva available
  let bytes <- takeAsciiCString window
  pure (String.ofList (bytes.map Char.ofNat))

def readImmutableCString (pe : PE32) (imports : List PEImport)
    (rva : Nat) : Option String :=
  readImmutableCStringFrom pe (immutableRvaBytes pe imports) rva

def decodeOptionalCStringFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer : Nat) : LayoutM (Option String) := do
  let target <- optionalPointerRva pe fieldRva pointer
  match target with
  | none => pure none
  | some rva =>
      let value <- LayoutM.ofOption (readImmutableCStringFrom pe readImmutable rva)
      pure (some value)

def decodeOptionalCString (pe : PE32) (imports : List PEImport)
    (fieldRva pointer : Nat) : LayoutM (Option String) :=
  decodeOptionalCStringFrom pe (immutableRvaBytes pe imports) fieldRva pointer

def decodeStackInputFrom (bytes : Bytes) (offset : Nat) : Option RawStackInput := do
  let stackOffset <- readStructU32 bytes offset
  let width <- readStructU32 bytes (offset + 4)
  let valueNode <- readStructU32 bytes (offset + 8)
  pure { offset := stackOffset, width, valueNode }

def decodeStackInputsFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer count : Nat) : LayoutM (List RawStackInput) := do
  let rva <- relocatedPointerRva pe fieldRva pointer
  let bytes <- LayoutM.ofOption
    (checkedArrayBytesFrom readImmutable
      rva count stackInputSize maxCallArguments 4)
  let inputs <- LayoutM.ofOption <|
    decodeOptionStride (fun tail => decodeStackInputFrom tail 0)
      stackInputSize count bytes
  pure inputs

def decodeStackInputs (pe : PE32) (imports : List PEImport)
    (fieldRva pointer count : Nat) : LayoutM (List RawStackInput) :=
  decodeStackInputsFrom pe (immutableRvaBytes pe imports) fieldRva pointer count

def decodeCallFromReader (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (callRva : Nat) (bytes : Bytes) (offset : Nat) : LayoutM RawCall := do
  let kind <- LayoutM.ofOption (readStructU32 bytes offset)
  let instructionRva <- LayoutM.ofOption (readStructU32 bytes (offset + 4))
  let callIndex <- LayoutM.ofOption (readStructU32 bytes (offset + 8))
  let targetNodeRaw <- LayoutM.ofOption (readStructU32 bytes (offset + 12))
  let targetRva <- LayoutM.ofOption (readStructU32 bytes (offset + 16))
  let returnRva <- LayoutM.ofOption (readStructU32 bytes (offset + 20))
  let dllPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 24))
  let symbolPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 28))
  let ordinalRaw <- LayoutM.ofOption (readStructU32 bytes (offset + 32))
  let hasOrdinal <- LayoutM.ofOption (readStructU32 bytes (offset + 36))
  let registerPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 40))
  let flagPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 44))
  let argumentPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 48))
  let argumentCount <- LayoutM.ofOption (readStructU32 bytes (offset + 52))
  let stackPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 56))
  let stackCount <- LayoutM.ofOption (readStructU32 bytes (offset + 60))
  LayoutM.guard (kind < 3 && argumentCount <= maxCallArguments &&
    stackCount <= maxCallArguments && hasOrdinal <= 1 &&
    (hasOrdinal != 0 || ordinalRaw == 0))
  let base := callRva + offset
  let dll <- decodeOptionalCStringFrom pe readImmutable (base + 24) dllPointer
  let symbol <- decodeOptionalCStringFrom pe readImmutable (base + 28) symbolPointer
  let registerNodes <- decodeU32ArrayFrom pe readImmutable
    (base + 40) registerPointer 8 8
  let flagNodes <- decodeU32ArrayFrom pe readImmutable
    (base + 44) flagPointer 6 6
  let argumentNodes <- decodeU32ArrayFrom pe readImmutable
    (base + 48) argumentPointer argumentCount maxCallArguments
  let stackInputs <- decodeStackInputsFrom pe readImmutable
    (base + 56) stackPointer stackCount
  pure {
    kind
    instructionRva
    callIndex
    targetNode := if kind == 2 then some targetNodeRaw else none
    targetRva
    returnRva
    dll
    symbol
    ordinal := if hasOrdinal == 1 then some ordinalRaw else none
    registerNodes
    flagNodes
    argumentNodes
    stackInputs
  }

def decodeCallFrom (pe : PE32) (imports : List PEImport)
    (callRva : Nat) (bytes : Bytes) (offset : Nat) : LayoutM RawCall :=
  decodeCallFromReader pe (immutableRvaBytes pe imports) callRva bytes offset

def callCountFromActions (actions : List RawAction) : Nat :=
  actions.foldl (fun count action =>
    match action.op, action.args with
    | 4, index :: _ => max count (index + 1)
    | _, _ => count) 0

def decodeCallArrayFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer count : Nat) : LayoutM (List RawCall) := do
  LayoutM.guard (count <= maxCalls)
  let rva <- relocatedPointerRva pe fieldRva pointer
  let bytes <- LayoutM.ofOption
    (checkedArrayBytesFrom readImmutable rva count callSize maxCalls 4)
  decodeLayoutStride (fun index tail =>
    decodeCallFromReader pe readImmutable (rva + index * callSize) tail 0)
    callSize 0 count bytes

def decodeCallArray (pe : PE32) (imports : List PEImport)
    (fieldRva pointer count : Nat) : LayoutM (List RawCall) :=
  decodeCallArrayFrom pe (immutableRvaBytes pe imports) fieldRva pointer count

def decodeX87ReplayFromReader (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (replayRva : Nat) (bytes : Bytes) (offset : Nat) : LayoutM RawX87Replay := do
  let imageBase <- LayoutM.ofOption (readStructU32 bytes offset)
  let rvaStart <- LayoutM.ofOption (readStructU32 bytes (offset + 4))
  let rvaEnd <- LayoutM.ofOption (readStructU32 bytes (offset + 8))
  let instructionCount <- LayoutM.ofOption (readStructU32 bytes (offset + 12))
  let byteCount <- LayoutM.ofOption (readStructU32 bytes (offset + 16))
  let bytePointer <- LayoutM.ofOption (readStructU32 bytes (offset + 20))
  let instructionHashPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 24))
  let transferHashPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 28))
  let contractHashPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 32))
  let decoderPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 36))
  let executorPointer <- LayoutM.ofOption (readStructU32 bytes (offset + 40))
  LayoutM.guard (instructionCount == 1 && byteCount != 0 && byteCount <= 15 &&
    rvaStart < rvaEnd && rvaEnd - rvaStart == byteCount)
  let base := replayRva + offset
  let instructionRva <- relocatedPointerRva pe (base + 20) bytePointer
  let instructionBytes <- LayoutM.ofOption
    (readImmutable instructionRva byteCount)
  let instructionBytesSha256 <- decodeOptionalCStringFrom pe readImmutable
    (base + 24) instructionHashPointer
  let transferInstructionBytesSha256 <- decodeOptionalCStringFrom pe readImmutable
    (base + 28) transferHashPointer
  let contractSha256 <- decodeOptionalCStringFrom pe readImmutable
    (base + 32) contractHashPointer
  let checkedDecoder <- decodeOptionalCStringFrom pe readImmutable
    (base + 36) decoderPointer
  let checkedExecutor <- decodeOptionalCStringFrom pe readImmutable
    (base + 40) executorPointer
  let instructionBytesSha256 <- LayoutM.ofOption instructionBytesSha256
  let transferInstructionBytesSha256 <- LayoutM.ofOption transferInstructionBytesSha256
  let contractSha256 <- LayoutM.ofOption contractSha256
  let checkedDecoder <- LayoutM.ofOption checkedDecoder
  let checkedExecutor <- LayoutM.ofOption checkedExecutor
  pure {
    imageBase
    rvaStart
    rvaEnd
    instructionCount
    instructionBytes
    instructionBytesSha256
    transferInstructionBytesSha256
    contractSha256
    checkedDecoder
    checkedExecutor
  }

def decodeX87ReplayFrom (pe : PE32) (imports : List PEImport)
    (replayRva : Nat) (bytes : Bytes) (offset : Nat) : LayoutM RawX87Replay :=
  decodeX87ReplayFromReader pe (immutableRvaBytes pe imports)
    replayRva bytes offset

def decodeX87ReplayArrayFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (fieldRva pointer count : Nat) : LayoutM (List RawX87Replay) := do
  LayoutM.guard (count <= maxX87Replays)
  let rva <- relocatedPointerRva pe fieldRva pointer
  let bytes <- LayoutM.ofOption
    (checkedArrayBytesFrom readImmutable
      rva count x87ReplaySize maxX87Replays 4)
  decodeLayoutStride (fun index tail =>
    decodeX87ReplayFromReader pe readImmutable
      (rva + index * x87ReplaySize) tail 0)
    x87ReplaySize 0 count bytes

def decodeX87ReplayArray (pe : PE32) (imports : List PEImport)
    (fieldRva pointer count : Nat) : LayoutM (List RawX87Replay) :=
  decodeX87ReplayArrayFrom pe (immutableRvaBytes pe imports)
    fieldRva pointer count

def decodeTransferDescriptorFrom (readImmutable : Nat -> Nat -> Option Bytes)
    (tableRva index : Nat) : Option TransferDescriptor := do
  let recordRva := tableRva + index * transferRecordSize
  let bytes <- readImmutable recordRva transferRecordSize
  let sourceRva <- readStructU32 bytes 0
  let wordCount <- readStructU32 bytes 4
  let x87Count <- readStructU32 bytes 8
  let actionCount <- readStructU32 bytes 12
  let replayCount <- readStructU32 bytes 16
  let wordPointer <- readStructU32 bytes 20
  let x87Pointer <- readStructU32 bytes 24
  let actionPointer <- readStructU32 bytes 28
  let callPointer <- readStructU32 bytes 32
  let replayPointer <- readStructU32 bytes 36
  pure {
    sourceRva
    wordCount
    x87Count
    actionCount
    replayCount
    wordPointer
    x87Pointer
    actionPointer
    callPointer
    replayPointer
  }

def decodeTransferDescriptor (pe : PE32) (imports : List PEImport)
    (tableRva index : Nat) : Option TransferDescriptor :=
  decodeTransferDescriptorFrom (immutableRvaBytes pe imports) tableRva index

def decodeTransferAtFrom (pe : PE32)
    (readImmutable : Nat -> Nat -> Option Bytes)
    (tableRva index : Nat) : LayoutM CompiledProgramRecord := do
  let recordRva := tableRva + index * transferRecordSize
  let descriptor <- LayoutM.ofOption
    (decodeTransferDescriptorFrom readImmutable tableRva index)
  LayoutM.guard (recordRva % 4 == 0 && descriptor.sourceRva < 2 ^ 32)
  let wordNodes <- decodeNodeArrayFrom pe readImmutable (recordRva + 20)
    descriptor.wordPointer descriptor.wordCount wordNodeSize maxWordNodes
  let x87Nodes <- decodeNodeArrayFrom pe readImmutable (recordRva + 24)
    descriptor.x87Pointer descriptor.x87Count x87NodeSize maxX87Nodes
  let actions <- decodeActionArrayFrom pe readImmutable (recordRva + 28)
    descriptor.actionPointer descriptor.actionCount
  let calls <- decodeCallArrayFrom pe readImmutable (recordRva + 32)
    descriptor.callPointer (callCountFromActions actions)
  let x87Replays <- decodeX87ReplayArrayFrom pe readImmutable (recordRva + 36)
    descriptor.replayPointer descriptor.replayCount
  pure {
    record := { sourceRva := descriptor.sourceRva, wordNodes, x87Nodes, calls, actions }
    x87Replays
  }

/-- The semantic-record decoder depends on the candidate image only through
`CandidateDataLayout`.  This theorem is the stable bridge that lets generated
local packs normalize a byte-free PE and lets the one global authority module
transport the result back to the exact parsed PE. -/
theorem decodeTransferAtFrom_dataLayout
    (pe : PE32) (readImmutable : Nat -> Nat -> Option Bytes)
    (tableRva index : Nat) :
    decodeTransferAtFrom pe readImmutable tableRva index =
      decodeTransferAtFrom (CandidateDataLayout.ofPE pe).asPE
        readImmutable tableRva index := by
  cases pe
  rfl

def decodeTransferAt (pe : PE32) (imports : List PEImport)
    (tableRva index : Nat) : LayoutM CompiledProgramRecord :=
  decodeTransferAtFrom pe (immutableRvaBytes pe imports) tableRva index

def decodeProgramTableRange (pe : PE32) (imports : List PEImport)
    (tableRva startIndex count : Nat) : LayoutM (List CompiledProgramRecord) := do
  LayoutM.guard (tableRva % 4 == 0 && startIndex + count < 2 ^ 32)
  decodeMany count fun offset => decodeTransferAt pe imports tableRva (startIndex + offset)

def readCompiledTransferCountFrom (readImmutable : Nat -> Nat -> Option Bytes)
    (countRva : Nat) : Option Nat := do
  if countRva % 4 != 0 then none else
  let bytes <- readImmutable countRva 4
  readU32 bytes 0

def readCompiledTransferCount (pe : PE32) (imports : List PEImport)
    (countRva : Nat) : Option Nat :=
  readCompiledTransferCountFrom (immutableRvaBytes pe imports) countRva

def relocationRvas (relocations : List BaseRelocation) : List Nat :=
  relocations.map (fun relocation => relocation.rva)

def relocationInventoryUniqueFrom (seen : List Nat) :
    List BaseRelocation -> Bool
  | [] => true
  | relocation :: tail =>
      (relocation.kind == 3 && !seen.contains relocation.rva) &&
        relocationInventoryUniqueFrom (relocation.rva :: seen) tail

def relocationInventoryUnique (relocations : List BaseRelocation) : Bool :=
  relocationInventoryUniqueFrom [] relocations

/-- A linear-time sufficient check for a HIGHLOW relocation inventory.
Strictly ascending RVAs imply uniqueness without searching the preceding
inventory for every relocation. -/
def relocationInventoryLinearChecked : List BaseRelocation -> Bool
  | [] => true
  | [relocation] => relocation.kind == 3
  | relocation :: next :: tail =>
      (relocation.kind == 3 && relocation.rva < next.rva) &&
        relocationInventoryLinearChecked (next :: tail)

private theorem pairwise_lt_nodup (values : List Nat)
    (ordered : values.Pairwise (fun left right => left < right)) :
    values.Nodup := by
  induction values with
  | nil => simp
  | cons head tail ih =>
      rw [List.pairwise_cons] at ordered
      rw [List.nodup_cons]
      constructor
      · intro headInTail
        exact (Nat.lt_irrefl head) (ordered.1 head headInTail)
      · exact ih ordered.2

private theorem relocationInventoryLinearChecked_kinds
    (relocations : List BaseRelocation)
    (checked : relocationInventoryLinearChecked relocations = true) :
    relocations.all (fun relocation => relocation.kind == 3) = true := by
  induction relocations with
  | nil => rfl
  | cons head tail ih =>
      cases tail with
      | nil => simpa [relocationInventoryLinearChecked] using checked
      | cons next rest =>
          change ((head.kind == 3 && head.rva < next.rva) &&
            relocationInventoryLinearChecked (next :: rest)) = true at checked
          have headChecked := Bool.and_eq_true_iff.mp
            (Bool.and_eq_true_iff.mp checked).1
          have tailChecked := (Bool.and_eq_true_iff.mp checked).2
          rw [List.all_cons, Bool.and_eq_true]
          exact ⟨headChecked.1, ih tailChecked⟩

private theorem relocationInventoryLinearChecked_ordered
    (relocations : List BaseRelocation)
    (checked : relocationInventoryLinearChecked relocations = true) :
    (relocationRvas relocations).Pairwise (fun left right => left < right) := by
  induction relocations with
  | nil => simp [relocationRvas]
  | cons head tail ih =>
      cases tail with
      | nil => simp [relocationRvas]
      | cons next rest =>
          change ((head.kind == 3 && head.rva < next.rva) &&
            relocationInventoryLinearChecked (next :: rest)) = true at checked
          have headChecked := Bool.and_eq_true_iff.mp
            (Bool.and_eq_true_iff.mp checked).1
          have headLt : head.rva < next.rva := of_decide_eq_true headChecked.2
          have tailChecked := (Bool.and_eq_true_iff.mp checked).2
          have tailOrdered := ih tailChecked
          have tailOrdered' :
              (next.rva :: relocationRvas rest).Pairwise
                (fun left right => left < right) := by
            simpa [relocationRvas] using tailOrdered
          have tailOrderedCons := List.pairwise_cons.mp tailOrdered'
          simp only [relocationRvas, List.map_cons, List.pairwise_cons]
          constructor
          · intro later laterIn
            simp only [List.mem_cons] at laterIn
            rcases laterIn with rfl | laterIn
            · exact headLt
            · exact Nat.lt_trans headLt (tailOrderedCons.1 later laterIn)
          · exact tailOrderedCons

private theorem relocationInventoryUniqueFrom_of_nodup
    (seen : List Nat) (relocations : List BaseRelocation)
    (kinds : relocations.all (fun relocation => relocation.kind == 3) = true)
    (unique : (relocationRvas relocations).Nodup)
    (fresh : ∀ relocation, relocation ∈ relocations -> relocation.rva ∉ seen) :
    relocationInventoryUniqueFrom seen relocations = true := by
  induction relocations generalizing seen with
  | nil => rfl
  | cons head tail ih =>
      rw [List.all_cons, Bool.and_eq_true] at kinds
      simp only [relocationRvas, List.map_cons, List.nodup_cons] at unique
      change ((head.kind == 3 && !seen.contains head.rva) &&
        relocationInventoryUniqueFrom (head.rva :: seen) tail) = true
      rw [Bool.and_eq_true, Bool.and_eq_true]
      refine ⟨⟨kinds.1, ?_⟩, ?_⟩
      · rw [Bool.not_eq_true', Bool.eq_false_iff]
        intro present
        exact fresh head (by simp) (List.contains_iff_mem.mp present)
      · apply ih (seen := head.rva :: seen) kinds.2 unique.2
        intro relocation relocationIn
        simp only [List.mem_cons, not_or]
        constructor
        · intro equal
          apply unique.1
          rw [List.mem_map]
          exact ⟨relocation, relocationIn, equal⟩
        · exact fresh relocation (by simp [relocationIn])

theorem relocationInventoryUnique_of_linearChecked
    (relocations : List BaseRelocation)
    (checked : relocationInventoryLinearChecked relocations = true) :
    relocationInventoryUnique relocations = true := by
  apply relocationInventoryUniqueFrom_of_nodup [] relocations
  · exact relocationInventoryLinearChecked_kinds relocations checked
  · exact pairwise_lt_nodup (relocationRvas relocations)
      (relocationInventoryLinearChecked_ordered relocations checked)
  · simp

def relocationFieldPresent (relocations : List BaseRelocation)
    (fieldRva : Nat) : Bool :=
  (relocationRvas relocations).any (· == fieldRva)

def relocationFieldAbsent (relocations : List BaseRelocation)
    (fieldRva : Nat) : Bool :=
  !relocationFieldPresent relocations fieldRva

/-! A bounded search tree over the exact parsed relocation inventory.  Branch
splits route a query to one fixed-size leaf; `InRange` proves that the skipped
subtree cannot contain the queried RVA. -/

inductive RelocationRvaIndex where
  | empty
  | leaf (values : List BaseRelocation)
  | branch (splitRva : Nat) (left right : RelocationRvaIndex)
deriving Repr, DecidableEq

namespace RelocationRvaIndex

def size : RelocationRvaIndex -> Nat
  | .empty => 0
  | .leaf values => values.length
  | .branch _ left right => left.size + right.size

def height : RelocationRvaIndex -> Nat
  | .empty => 0
  | .leaf _ => 1
  | .branch _ left right => 1 + max left.height right.height

def toList : RelocationRvaIndex -> List BaseRelocation
  | .empty => []
  | .leaf values => values
  | .branch _ left right => left.toList ++ right.toList

def contains : RelocationRvaIndex -> Nat -> Bool
  | .empty, _ => false
  | .leaf values, fieldRva => values.any (fun relocation =>
      relocation.rva == fieldRva)
  | .branch splitRva left right, fieldRva =>
      if fieldRva < splitRva then left.contains fieldRva
      else right.contains fieldRva

def leavesBounded (leafCapacity : Nat) : RelocationRvaIndex -> Bool
  | .empty => true
  | .leaf values => !values.isEmpty && values.length <= leafCapacity
  | .branch _ left right =>
      left.leavesBounded leafCapacity && right.leavesBounded leafCapacity

def branchesNonempty : RelocationRvaIndex -> Bool
  | .empty | .leaf _ => true
  | .branch _ left right =>
      left.size != 0 && right.size != 0 &&
        left.branchesNonempty && right.branchesNonempty

def balanced : RelocationRvaIndex -> Bool
  | .empty | .leaf _ => true
  | .branch _ left right =>
      left.height <= right.height + 1 && right.height <= left.height + 1 &&
        left.balanced && right.balanced

def structurallyValid (leafCapacity : Nat) (index : RelocationRvaIndex) : Bool :=
  index.leavesBounded leafCapacity && index.branchesNonempty && index.balanced

def InRange : RelocationRvaIndex -> Nat -> Nat -> Prop
  | .empty, _, _ => True
  | .leaf values, lower, upper => forall relocation, relocation ∈ values ->
      lower <= relocation.rva /\ relocation.rva < upper
  | .branch splitRva left right, lower, upper =>
      lower < splitRva /\ splitRva < upper /\
        left.InRange lower splitRva /\ right.InRange splitRva upper

def rangesChecked : RelocationRvaIndex -> Nat -> Nat -> Bool
  | .empty, _, _ => true
  | .leaf values, lower, upper => values.all (fun relocation =>
      lower <= relocation.rva && relocation.rva < upper)
  | .branch splitRva left right, lower, upper =>
      lower < splitRva && splitRva < upper &&
        left.rangesChecked lower splitRva && right.rangesChecked splitRva upper

theorem inRange_of_checked (index : RelocationRvaIndex) (lower upper : Nat)
    (checked : index.rangesChecked lower upper = true) :
    index.InRange lower upper := by
  induction index generalizing lower upper with
  | empty => trivial
  | leaf values =>
      intro relocation member
      have item := List.all_eq_true.mp checked relocation member
      simpa [rangesChecked] using item
  | branch splitRva left right leftIH rightIH =>
      simp only [rangesChecked, Bool.and_eq_true, decide_eq_true_eq] at checked
      rcases checked with ⟨⟨⟨lowerSplit, splitUpper⟩, leftChecked⟩,
        rightChecked⟩
      exact ⟨lowerSplit, splitUpper, leftIH _ _ leftChecked,
        rightIH _ _ rightChecked⟩

theorem lower_le_of_inRange (index : RelocationRvaIndex)
    (ranges : index.InRange lower upper) (relocation : BaseRelocation)
    (member : relocation ∈ index.toList) : lower <= relocation.rva := by
  induction index generalizing lower upper with
  | empty => simp [toList] at member
  | leaf values => exact (ranges relocation member).1
  | branch splitRva left right leftIH rightIH =>
      rcases ranges with ⟨lowerSplit, splitUpper, leftRanges, rightRanges⟩
      rw [toList, List.mem_append] at member
      cases member with
      | inl member => exact leftIH leftRanges member
      | inr member =>
          exact Nat.le_trans (Nat.le_of_lt lowerSplit)
            (rightIH rightRanges member)

theorem lt_upper_of_inRange (index : RelocationRvaIndex)
    (ranges : index.InRange lower upper) (relocation : BaseRelocation)
    (member : relocation ∈ index.toList) : relocation.rva < upper := by
  induction index generalizing lower upper with
  | empty => simp [toList] at member
  | leaf values => exact (ranges relocation member).2
  | branch splitRva left right leftIH rightIH =>
      rcases ranges with ⟨lowerSplit, splitUpper, leftRanges, rightRanges⟩
      rw [toList, List.mem_append] at member
      cases member with
      | inl member =>
          exact Nat.lt_trans (leftIH leftRanges member) splitUpper
      | inr member => exact rightIH rightRanges member

theorem contains_eq_true_iff_mem (index : RelocationRvaIndex)
    (ranges : index.InRange lower upper) (fieldRva : Nat) :
    index.contains fieldRva = true <->
      fieldRva ∈ relocationRvas index.toList := by
  induction index generalizing lower upper with
  | empty => simp [contains, toList, relocationRvas]
  | leaf values => simp [contains, toList, relocationRvas]
  | branch splitRva left right leftIH rightIH =>
      rcases ranges with ⟨lowerSplit, splitUpper, leftRanges, rightRanges⟩
      by_cases before : fieldRva < splitRva
      · have notRight : fieldRva ∉ relocationRvas right.toList := by
          intro member
          simp only [relocationRvas] at member
          rw [List.mem_map] at member
          rcases member with ⟨relocation, member, equal⟩
          have bound := right.lower_le_of_inRange rightRanges relocation member
          omega
        simp only [contains, before, ↓reduceIte, toList, relocationRvas,
          List.map_append, List.mem_append]
        rw [leftIH leftRanges]
        constructor
        · exact Or.inl
        · intro member
          exact member.elim id (fun impossible => False.elim (notRight impossible))
      · have notLeft : fieldRva ∉ relocationRvas left.toList := by
          intro member
          simp only [relocationRvas] at member
          rw [List.mem_map] at member
          rcases member with ⟨relocation, member, equal⟩
          have bound := left.lt_upper_of_inRange leftRanges relocation member
          omega
        simp only [contains, before, ↓reduceIte, toList, relocationRvas,
          List.map_append, List.mem_append]
        rw [rightIH rightRanges]
        constructor
        · exact Or.inr
        · intro member
          exact member.elim (fun impossible => False.elim (notLeft impossible)) id

end RelocationRvaIndex

structure RelocationRvaIndexCertificate
    (relocations : List BaseRelocation) where
  index : RelocationRvaIndex
  leafCapacity : Nat
  structurallyValid : index.structurallyValid leafCapacity = true
  rangesChecked : index.rangesChecked 0 (2 ^ 32) = true
  authoritative : index.toList = relocations

theorem RelocationRvaIndexCertificate.contains_eq_present
    (certificate : RelocationRvaIndexCertificate relocations)
    (fieldRva : Nat) :
    certificate.index.contains fieldRva =
      relocationFieldPresent relocations fieldRva := by
  rw [Bool.eq_iff_iff]
  rw [certificate.index.contains_eq_true_iff_mem
    (certificate.index.inRange_of_checked 0 (2 ^ 32) certificate.rangesChecked)]
  rw [certificate.authoritative]
  simp [relocationFieldPresent]

def LayoutTrace.relocationFieldsChecked (trace : LayoutTrace)
    (relocations : List BaseRelocation) : Bool :=
  trace.relocatedPointerFields.all (relocationFieldPresent relocations) &&
    trace.zeroPointerFields.all (relocationFieldAbsent relocations)

/-- Per-field positive relocation evidence.  Generated leaves reduce exactly
one inventory lookup; list composition never re-runs another lookup. -/
inductive RelocationPresenceCertificate (relocations : List BaseRelocation) :
    List Nat -> Prop where
  | nil : RelocationPresenceCertificate relocations []
  | cons (checked : relocationFieldPresent relocations fieldRva = true)
      (tail : RelocationPresenceCertificate relocations fields) :
      RelocationPresenceCertificate relocations (fieldRva :: fields)

/-- Per-field negative relocation evidence for a pointer encoded as zero. -/
inductive RelocationAbsenceCertificate (relocations : List BaseRelocation) :
    List Nat -> Prop where
  | nil : RelocationAbsenceCertificate relocations []
  | cons (checked : relocationFieldAbsent relocations fieldRva = true)
      (tail : RelocationAbsenceCertificate relocations fields) :
      RelocationAbsenceCertificate relocations (fieldRva :: fields)

theorem RelocationPresenceCertificate.all_checked
    (certificate : RelocationPresenceCertificate relocations fields) :
    fields.all (relocationFieldPresent relocations) = true := by
  induction certificate with
  | nil => rfl
  | cons checked _ induction =>
      simpa [checked] using induction

theorem RelocationAbsenceCertificate.all_checked
    (certificate : RelocationAbsenceCertificate relocations fields) :
    fields.all (relocationFieldAbsent relocations) = true := by
  induction certificate with
  | nil => rfl
  | cons checked _ induction =>
      simpa [checked] using induction

def RelocationPresenceCertificate.of_all_checked
    (checked : fields.all (relocationFieldPresent relocations) = true) :
    RelocationPresenceCertificate relocations fields := by
  induction fields with
  | nil => exact .nil
  | cons head tail induction =>
      rw [List.all_cons, Bool.and_eq_true] at checked
      exact .cons checked.1 (induction checked.2)

def RelocationAbsenceCertificate.of_all_checked
    (checked : fields.all (relocationFieldAbsent relocations) = true) :
    RelocationAbsenceCertificate relocations fields := by
  induction fields with
  | nil => exact .nil
  | cons head tail induction =>
      rw [List.all_cons, Bool.and_eq_true] at checked
      exact .cons checked.1 (induction checked.2)

def RelocationPresenceCertificate.of_indexed
    (certificate : RelocationRvaIndexCertificate relocations)
    (fields : List Nat)
    (checked : fields.all certificate.index.contains = true) :
    RelocationPresenceCertificate relocations fields := by
  induction fields with
  | nil => exact .nil
  | cons field fields induction =>
      rw [List.all_cons, Bool.and_eq_true] at checked
      exact .cons (by
        rw [<- certificate.contains_eq_present]
        exact checked.1) (induction checked.2)

def RelocationAbsenceCertificate.of_indexed
    (certificate : RelocationRvaIndexCertificate relocations)
    (fields : List Nat)
    (checked : fields.all (fun field => !certificate.index.contains field) = true) :
    RelocationAbsenceCertificate relocations fields := by
  induction fields with
  | nil => exact .nil
  | cons field fields induction =>
      rw [List.all_cons, Bool.and_eq_true] at checked
      exact .cons (by
        rw [relocationFieldAbsent, <- certificate.contains_eq_present]
        exact checked.1) (induction checked.2)

theorem RelocationPresenceCertificate.append
    (left : RelocationPresenceCertificate relocations leftFields)
    (right : RelocationPresenceCertificate relocations rightFields) :
    RelocationPresenceCertificate relocations (leftFields ++ rightFields) := by
  induction left with
  | nil => exact right
  | cons checked _ induction =>
      exact .cons checked induction

theorem RelocationAbsenceCertificate.append
    (left : RelocationAbsenceCertificate relocations leftFields)
    (right : RelocationAbsenceCertificate relocations rightFields) :
    RelocationAbsenceCertificate relocations (leftFields ++ rightFields) := by
  induction left with
  | nil => exact right
  | cons checked _ induction =>
      exact .cons checked induction

/-- A trace certificate is structural: every relocated field has a checked
present leaf and every zero field has a checked absent leaf. -/
structure LayoutTraceRelocationCertificate (trace : LayoutTrace)
    (relocations : List BaseRelocation) : Prop where
  relocated : RelocationPresenceCertificate relocations
    trace.relocatedPointerFields
  zero : RelocationAbsenceCertificate relocations trace.zeroPointerFields

def LayoutTraceRelocationCertificate.empty (relocations : List BaseRelocation) :
    LayoutTraceRelocationCertificate ({} : LayoutTrace) relocations := {
  relocated := .nil
  zero := .nil
}

theorem LayoutTraceRelocationCertificate.append
    (left : LayoutTraceRelocationCertificate leftTrace relocations)
    (right : LayoutTraceRelocationCertificate rightTrace relocations) :
    LayoutTraceRelocationCertificate (leftTrace.append rightTrace) relocations := {
  relocated := left.relocated.append right.relocated
  zero := left.zero.append right.zero
}

theorem LayoutTraceRelocationCertificate.checked
    (certificate : LayoutTraceRelocationCertificate trace relocations) :
    trace.relocationFieldsChecked relocations = true := by
  rw [LayoutTrace.relocationFieldsChecked, Bool.and_eq_true]
  exact ⟨certificate.relocated.all_checked, certificate.zero.all_checked⟩

def LayoutTraceRelocationCertificate.of_checked
    (checked : trace.relocationFieldsChecked relocations = true) :
    LayoutTraceRelocationCertificate trace relocations := by
  rw [LayoutTrace.relocationFieldsChecked, Bool.and_eq_true] at checked
  exact {
    relocated := .of_all_checked checked.1
    zero := .of_all_checked checked.2
  }

/-- Exact decoded value plus independently composed pointer-field evidence.
Unlike a Boolean equality over a complete shard, this certificate keeps the
concrete trace available for cacheable record and range composition. -/
structure LayoutMExactCertificate (decoded : LayoutM alpha) (expected : alpha)
    (relocations : List BaseRelocation) where
  trace : LayoutTrace
  decodedExact : decoded = .ok expected trace
  relocationFields : LayoutTraceRelocationCertificate trace relocations

def layoutMExactChecked (decoded : LayoutM alpha) (expected : alpha)
    (trace : LayoutTrace) (relocations : List BaseRelocation) [DecidableEq alpha] :
    Bool :=
  decide (decoded = .ok expected trace) &&
    trace.relocationFieldsChecked relocations

def LayoutMExactCertificate.of_checked {alpha : Type} [DecidableEq alpha]
    {decoded : LayoutM alpha} {expected : alpha} {trace : LayoutTrace}
    {relocations : List BaseRelocation}
    (checked : layoutMExactChecked decoded expected trace relocations = true) :
    LayoutMExactCertificate decoded expected relocations := by
  rw [layoutMExactChecked, Bool.and_eq_true] at checked
  exact {
    trace
    decodedExact := of_decide_eq_true checked.1
    relocationFields := .of_checked checked.2
  }

def LayoutMExactCertificate.pure (value : alpha)
    (relocations : List BaseRelocation) :
    LayoutMExactCertificate (LayoutM.pure value) value relocations := {
  trace := {}
  decodedExact := rfl
  relocationFields := .empty relocations
}

def LayoutMExactCertificate.listCons
    (head : LayoutMExactCertificate decodedHead expectedHead relocations)
    (tail : LayoutMExactCertificate decodedTail expectedTail relocations) :
    LayoutMExactCertificate (do
      let headValue <- decodedHead
      let tailValue <- decodedTail
      LayoutM.pure (headValue :: tailValue))
      (expectedHead :: expectedTail) relocations := by
  rcases head with ⟨headTrace, headExact, headFields⟩
  rcases tail with ⟨tailTrace, tailExact, tailFields⟩
  refine {
    trace := headTrace.append tailTrace
    decodedExact := ?_
    relocationFields := headFields.append tailFields
  }
  rw [headExact, tailExact]
  simp [LayoutM.pure, LayoutTrace.append]

def decodeManyAuxNilCertificate (decode : Nat -> LayoutM alpha) (index : Nat)
    (relocations : List BaseRelocation) :
    LayoutMExactCertificate (decodeManyAux decode index 0) [] relocations := by
  simpa [decodeManyAux] using LayoutMExactCertificate.pure [] relocations

def decodeManyAuxConsCertificate (decode : Nat -> LayoutM alpha)
    (index count : Nat) (relocations : List BaseRelocation)
    (head : LayoutMExactCertificate (decode index) expectedHead relocations)
    (tail : LayoutMExactCertificate (decodeManyAux decode (index + 1) count)
      expectedTail relocations) :
    LayoutMExactCertificate (decodeManyAux decode index (count + 1))
      (expectedHead :: expectedTail) relocations := by
  simpa [decodeManyAux] using head.listCons tail

def decodeProgramTableRangeCertificate
    (pe : PE32) (imports : List PEImport) (tableRva startIndex count : Nat)
    (entries : List CompiledProgramRecord) (relocations : List BaseRelocation)
    (guardChecked :
      (tableRva % 4 == 0 && startIndex + count < 2 ^ 32) = true)
    (many : LayoutMExactCertificate
      (decodeMany count fun offset =>
        decodeTransferAt pe imports tableRva (startIndex + offset))
      entries relocations) :
    LayoutMExactCertificate
      (decodeProgramTableRange pe imports tableRva startIndex count)
      entries relocations := by
  rcases many with ⟨trace, decodedExact, fields⟩
  refine {
    trace
    decodedExact := ?_
    relocationFields := fields
  }
  unfold decodeProgramTableRange
  rw [guardChecked]
  rw [decodedExact]
  simp [LayoutM.guard, LayoutTrace.append]

theorem decodeTransferAtFrom_eq_of_components
    (pe : PE32) (readImmutable : Nat -> Nat -> Option Bytes)
    (tableRva index : Nat)
    (descriptor : TransferDescriptor)
    (wordNodes x87Nodes : List RawWordNode)
    (actions : List RawAction) (calls : List RawCall)
    (x87Replays : List RawX87Replay)
    (wordTrace x87Trace actionTrace callTrace replayTrace : LayoutTrace)
    (descriptorDecoded :
      decodeTransferDescriptorFrom readImmutable tableRva index = some descriptor)
    (descriptorValid :
      ((tableRva + index * transferRecordSize) % 4 == 0 &&
        descriptor.sourceRva < 2 ^ 32) = true)
    (wordDecoded : decodeNodeArrayFrom pe readImmutable
      (tableRva + index * transferRecordSize + 20)
      descriptor.wordPointer descriptor.wordCount wordNodeSize maxWordNodes =
        .ok wordNodes wordTrace)
    (x87Decoded : decodeNodeArrayFrom pe readImmutable
      (tableRva + index * transferRecordSize + 24)
      descriptor.x87Pointer descriptor.x87Count x87NodeSize maxX87Nodes =
        .ok x87Nodes x87Trace)
    (actionsDecoded : decodeActionArrayFrom pe readImmutable
      (tableRva + index * transferRecordSize + 28)
      descriptor.actionPointer descriptor.actionCount =
        .ok actions actionTrace)
    (callsDecoded : decodeCallArrayFrom pe readImmutable
      (tableRva + index * transferRecordSize + 32)
      descriptor.callPointer (callCountFromActions actions) =
        .ok calls callTrace)
    (replaysDecoded : decodeX87ReplayArrayFrom pe readImmutable
      (tableRva + index * transferRecordSize + 36)
      descriptor.replayPointer descriptor.replayCount =
        .ok x87Replays replayTrace) :
    decodeTransferAtFrom pe readImmutable tableRva index = .ok {
      record := {
        sourceRva := descriptor.sourceRva
        wordNodes
        x87Nodes
        calls
        actions
      }
      x87Replays
    } (wordTrace.append (x87Trace.append (actionTrace.append
      (callTrace.append replayTrace)))) := by
  have valid := Bool.and_eq_true_iff.mp descriptorValid
  have aligned : (tableRva + index * transferRecordSize) % 4 = 0 :=
    of_decide_eq_true valid.1
  have sourceBound : descriptor.sourceRva < 2 ^ 32 :=
    of_decide_eq_true valid.2
  simp [decodeTransferAtFrom, descriptorDecoded,
    aligned, sourceBound, wordDecoded, x87Decoded,
    actionsDecoded, callsDecoded, replaysDecoded, LayoutM.ofOption,
    LayoutM.guard, LayoutTrace.append]

theorem decodeTransferAt_eq_of_components
    (pe : PE32) (imports : List PEImport) (tableRva index : Nat)
    (descriptor : TransferDescriptor)
    (wordNodes x87Nodes : List RawWordNode)
    (actions : List RawAction) (calls : List RawCall)
    (x87Replays : List RawX87Replay)
    (wordTrace x87Trace actionTrace callTrace replayTrace : LayoutTrace)
    (descriptorDecoded :
      decodeTransferDescriptor pe imports tableRva index = some descriptor)
    (descriptorValid :
      ((tableRva + index * transferRecordSize) % 4 == 0 &&
        descriptor.sourceRva < 2 ^ 32) = true)
    (wordDecoded : decodeNodeArray pe imports
      (tableRva + index * transferRecordSize + 20)
      descriptor.wordPointer descriptor.wordCount wordNodeSize maxWordNodes =
        .ok wordNodes wordTrace)
    (x87Decoded : decodeNodeArray pe imports
      (tableRva + index * transferRecordSize + 24)
      descriptor.x87Pointer descriptor.x87Count x87NodeSize maxX87Nodes =
        .ok x87Nodes x87Trace)
    (actionsDecoded : decodeActionArray pe imports
      (tableRva + index * transferRecordSize + 28)
      descriptor.actionPointer descriptor.actionCount =
        .ok actions actionTrace)
    (callsDecoded : decodeCallArray pe imports
      (tableRva + index * transferRecordSize + 32)
      descriptor.callPointer (callCountFromActions actions) =
        .ok calls callTrace)
    (replaysDecoded : decodeX87ReplayArray pe imports
      (tableRva + index * transferRecordSize + 36)
      descriptor.replayPointer descriptor.replayCount =
        .ok x87Replays replayTrace) :
    decodeTransferAt pe imports tableRva index = .ok {
      record := {
        sourceRva := descriptor.sourceRva
        wordNodes
        x87Nodes
        calls
        actions
      }
      x87Replays
    } (wordTrace.append (x87Trace.append (actionTrace.append
      (callTrace.append replayTrace)))) := by
  exact decodeTransferAtFrom_eq_of_components pe
    (immutableRvaBytes pe imports) tableRva index descriptor wordNodes x87Nodes
    actions calls x87Replays wordTrace x87Trace actionTrace callTrace replayTrace
    descriptorDecoded descriptorValid wordDecoded x87Decoded actionsDecoded
    callsDecoded replaysDecoded

def transferDescriptorChecked (pe : PE32) (imports : List PEImport)
    (tableRva index : Nat) (data : TransferCertificateData) : Bool :=
  decide (decodeTransferDescriptor pe imports tableRva index = some data.descriptor) &&
    ((tableRva + index * transferRecordSize) % 4 == 0 &&
      data.descriptor.sourceRva < 2 ^ 32)

def transferWordNodesChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (data : TransferCertificateData) : Bool :=
  layoutMExactChecked
    (decodeNodeArray pe imports
      (tableRva + index * transferRecordSize + 20)
      data.descriptor.wordPointer data.descriptor.wordCount wordNodeSize maxWordNodes)
    data.wordNodes data.wordTrace relocations

def transferX87NodesChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (data : TransferCertificateData) : Bool :=
  layoutMExactChecked
    (decodeNodeArray pe imports
      (tableRva + index * transferRecordSize + 24)
      data.descriptor.x87Pointer data.descriptor.x87Count x87NodeSize maxX87Nodes)
    data.x87Nodes data.x87Trace relocations

def transferActionsChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (data : TransferCertificateData) : Bool :=
  layoutMExactChecked
    (decodeActionArray pe imports
      (tableRva + index * transferRecordSize + 28)
      data.descriptor.actionPointer data.descriptor.actionCount)
    data.actions data.actionTrace relocations

def transferCallsChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (data : TransferCertificateData) : Bool :=
  layoutMExactChecked
    (decodeCallArray pe imports
      (tableRva + index * transferRecordSize + 32)
      data.descriptor.callPointer (callCountFromActions data.actions))
    data.calls data.callTrace relocations

def transferX87ReplaysChecked (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva index : Nat)
    (data : TransferCertificateData) : Bool :=
  layoutMExactChecked
    (decodeX87ReplayArray pe imports
      (tableRva + index * transferRecordSize + 36)
      data.descriptor.replayPointer data.descriptor.replayCount)
    data.x87Replays data.replayTrace relocations

def transferCertificateExactOfChecked
    (pe : PE32) (imports : List PEImport) (relocations : List BaseRelocation)
    (tableRva index : Nat) (data : TransferCertificateData)
    (descriptorChecked : transferDescriptorChecked pe imports tableRva index data = true)
    (wordChecked : transferWordNodesChecked pe imports relocations tableRva index data = true)
    (x87Checked : transferX87NodesChecked pe imports relocations tableRva index data = true)
    (actionsChecked : transferActionsChecked pe imports relocations tableRva index data = true)
    (callsChecked : transferCallsChecked pe imports relocations tableRva index data = true)
    (replaysChecked : transferX87ReplaysChecked pe imports relocations tableRva index data = true) :
    LayoutMExactCertificate (decodeTransferAt pe imports tableRva index)
      data.compiled relocations := by
  rw [transferDescriptorChecked, Bool.and_eq_true] at descriptorChecked
  have descriptorDecoded :
      decodeTransferDescriptor pe imports tableRva index = some data.descriptor :=
    of_decide_eq_true descriptorChecked.1
  unfold transferWordNodesChecked at wordChecked
  unfold transferX87NodesChecked at x87Checked
  unfold transferActionsChecked at actionsChecked
  unfold transferCallsChecked at callsChecked
  unfold transferX87ReplaysChecked at replaysChecked
  rw [layoutMExactChecked, Bool.and_eq_true] at wordChecked
  rw [layoutMExactChecked, Bool.and_eq_true] at x87Checked
  rw [layoutMExactChecked, Bool.and_eq_true] at actionsChecked
  rw [layoutMExactChecked, Bool.and_eq_true] at callsChecked
  rw [layoutMExactChecked, Bool.and_eq_true] at replaysChecked
  refine {
    trace := data.wordTrace.append (data.x87Trace.append
      (data.actionTrace.append (data.callTrace.append data.replayTrace)))
    decodedExact := ?_
    relocationFields :=
      (LayoutTraceRelocationCertificate.of_checked wordChecked.2).append
        ((LayoutTraceRelocationCertificate.of_checked x87Checked.2).append
          ((LayoutTraceRelocationCertificate.of_checked actionsChecked.2).append
            ((LayoutTraceRelocationCertificate.of_checked callsChecked.2).append
              (LayoutTraceRelocationCertificate.of_checked replaysChecked.2))))
  }
  simpa [TransferCertificateData.compiled] using
    decodeTransferAt_eq_of_components pe imports tableRva index data.descriptor
      data.wordNodes data.x87Nodes data.actions data.calls data.x87Replays
      data.wordTrace data.x87Trace data.actionTrace data.callTrace data.replayTrace
      descriptorDecoded descriptorChecked.2 (of_decide_eq_true wordChecked.1)
      (of_decide_eq_true x87Checked.1) (of_decide_eq_true actionsChecked.1)
      (of_decide_eq_true callsChecked.1) (of_decide_eq_true replaysChecked.1)

def transferCertificateListChecked
    (check : Nat -> TransferCertificateData -> Bool) :
    Nat -> List TransferCertificateData -> Bool
  | _, [] => true
  | index, head :: tail =>
      check index head && transferCertificateListChecked check (index + 1) tail

def TransferCertificatePack.checked (pack : TransferCertificatePack)
    (leafCapacity : Nat) (check : Nat -> TransferCertificateData -> Bool) : Bool :=
  pack.entries.structurallyValid leafCapacity &&
    transferCertificateListChecked check pack.startIndex pack.entries.toList

noncomputable def transferCertificateListExact
    (pe : PE32) (imports : List PEImport) (relocations : List BaseRelocation)
    (tableRva startIndex : Nat) (entries : List TransferCertificateData)
    (descriptorsChecked : transferCertificateListChecked
      (transferDescriptorChecked pe imports tableRva) startIndex entries = true)
    (wordsChecked : transferCertificateListChecked
      (transferWordNodesChecked pe imports relocations tableRva) startIndex entries = true)
    (x87sChecked : transferCertificateListChecked
      (transferX87NodesChecked pe imports relocations tableRva) startIndex entries = true)
    (actionsChecked : transferCertificateListChecked
      (transferActionsChecked pe imports relocations tableRva) startIndex entries = true)
    (callsChecked : transferCertificateListChecked
      (transferCallsChecked pe imports relocations tableRva) startIndex entries = true)
    (replaysChecked : transferCertificateListChecked
      (transferX87ReplaysChecked pe imports relocations tableRva) startIndex entries = true) :
    LayoutMExactCertificate
      (decodeManyAux (fun index => decodeTransferAt pe imports tableRva index)
        startIndex entries.length)
      (entries.map TransferCertificateData.compiled) relocations := by
  induction entries generalizing startIndex with
  | nil => exact decodeManyAuxNilCertificate _ startIndex relocations
  | cons head tail induction =>
      rw [transferCertificateListChecked, Bool.and_eq_true] at descriptorsChecked
      rw [transferCertificateListChecked, Bool.and_eq_true] at wordsChecked
      rw [transferCertificateListChecked, Bool.and_eq_true] at x87sChecked
      rw [transferCertificateListChecked, Bool.and_eq_true] at actionsChecked
      rw [transferCertificateListChecked, Bool.and_eq_true] at callsChecked
      rw [transferCertificateListChecked, Bool.and_eq_true] at replaysChecked
      have headCertificate := transferCertificateExactOfChecked pe imports relocations
        tableRva startIndex head descriptorsChecked.1 wordsChecked.1 x87sChecked.1
        actionsChecked.1 callsChecked.1 replaysChecked.1
      have tailCertificate := induction (startIndex := startIndex + 1)
        descriptorsChecked.2 wordsChecked.2 x87sChecked.2 actionsChecked.2
        callsChecked.2 replaysChecked.2
      simpa using decodeManyAuxConsCertificate
        (fun index => decodeTransferAt pe imports tableRva index)
        startIndex tail.length relocations headCertificate tailCertificate

noncomputable def TransferCertificatePack.exactCertificate
    (pack : TransferCertificatePack) (leafCapacity : Nat)
    (pe : PE32) (imports : List PEImport) (relocations : List BaseRelocation)
    (tableRva : Nat)
    (descriptorsChecked : pack.checked leafCapacity
      (transferDescriptorChecked pe imports tableRva) = true)
    (wordsChecked : pack.checked leafCapacity
      (transferWordNodesChecked pe imports relocations tableRva) = true)
    (x87sChecked : pack.checked leafCapacity
      (transferX87NodesChecked pe imports relocations tableRva) = true)
    (actionsChecked : pack.checked leafCapacity
      (transferActionsChecked pe imports relocations tableRva) = true)
    (callsChecked : pack.checked leafCapacity
      (transferCallsChecked pe imports relocations tableRva) = true)
    (replaysChecked : pack.checked leafCapacity
      (transferX87ReplaysChecked pe imports relocations tableRva) = true) :
    LayoutMExactCertificate
      (decodeManyAux (fun index => decodeTransferAt pe imports tableRva index)
        pack.startIndex pack.entries.toList.length)
      (pack.entries.toList.map TransferCertificateData.compiled) relocations := by
  rw [TransferCertificatePack.checked, Bool.and_eq_true] at descriptorsChecked
  rw [TransferCertificatePack.checked, Bool.and_eq_true] at wordsChecked
  rw [TransferCertificatePack.checked, Bool.and_eq_true] at x87sChecked
  rw [TransferCertificatePack.checked, Bool.and_eq_true] at actionsChecked
  rw [TransferCertificatePack.checked, Bool.and_eq_true] at callsChecked
  rw [TransferCertificatePack.checked, Bool.and_eq_true] at replaysChecked
  exact transferCertificateListExact pe imports relocations tableRva pack.startIndex
    pack.entries.toList descriptorsChecked.2 wordsChecked.2 x87sChecked.2
    actionsChecked.2 callsChecked.2 replaysChecked.2

/-- The durable generated checker.  Decoding runs against a small exact cache,
then one opaque reader-equality theorem transports the result back to the
authoritative PE.  Each relocation check follows one path to a bounded leaf in
the separately checked relocation index. -/
def transferLocalCertificateChecked
    (cache : ImmutableByteCache pe imports)
    (relocationIndex : RelocationRvaIndexCertificate relocations)
    (tableRva index : Nat) (data : TransferCertificateData) : Bool :=
  decide (decodeTransferAtFrom pe cache.read tableRva index =
    .ok data.compiled data.trace) &&
    (data.trace.relocatedPointerFields.all relocationIndex.index.contains &&
    data.trace.zeroPointerFields.all (fun field =>
      !relocationIndex.index.contains field))

def TransferCertificatePack.localChecked
    (pack : TransferCertificatePack) (leafCapacity rangeLeafCapacity : Nat)
    (cache : ImmutableByteCache pe imports)
    (relocationIndex : RelocationRvaIndexCertificate relocations)
    (tableRva : Nat) : Bool :=
  pack.entries.structurallyValid leafCapacity &&
    (cache.ranges.structurallyValid rangeLeafCapacity &&
    transferCertificateListChecked
      (transferLocalCertificateChecked cache relocationIndex tableRva)
      pack.startIndex pack.entries.toList)

def transferLocalCertificateExactOfChecked
    (cache : ImmutableByteCache pe imports)
    (relocationIndex : RelocationRvaIndexCertificate relocations)
    (tableRva index : Nat) (data : TransferCertificateData)
    (checked : transferLocalCertificateChecked cache relocationIndex
      tableRva index data = true) :
    LayoutMExactCertificate (decodeTransferAt pe imports tableRva index)
      data.compiled relocations := by
  rw [transferLocalCertificateChecked, Bool.and_eq_true,
    Bool.and_eq_true] at checked
  have localDecoded : decodeTransferAtFrom pe cache.read tableRva index =
      .ok data.compiled data.trace := of_decide_eq_true checked.1
  refine {
    trace := data.trace
    decodedExact := ?_
    relocationFields := {
      relocated := RelocationPresenceCertificate.of_indexed relocationIndex
        data.trace.relocatedPointerFields checked.2.1
      zero := RelocationAbsenceCertificate.of_indexed relocationIndex
        data.trace.zeroPointerFields checked.2.2
    }
  }
  rw [decodeTransferAt, <- cache.read_eq_authoritative]
  exact localDecoded

noncomputable def transferLocalCertificateListExact
    (cache : ImmutableByteCache pe imports)
    (relocationIndex : RelocationRvaIndexCertificate relocations)
    (tableRva startIndex : Nat) (entries : List TransferCertificateData)
    (checked : transferCertificateListChecked
      (transferLocalCertificateChecked cache relocationIndex tableRva)
      startIndex entries = true) :
    LayoutMExactCertificate
      (decodeManyAux (fun index => decodeTransferAt pe imports tableRva index)
        startIndex entries.length)
      (entries.map TransferCertificateData.compiled) relocations := by
  induction entries generalizing startIndex with
  | nil => exact decodeManyAuxNilCertificate _ startIndex relocations
  | cons head tail induction =>
      rw [transferCertificateListChecked, Bool.and_eq_true] at checked
      exact decodeManyAuxConsCertificate
        (fun index => decodeTransferAt pe imports tableRva index)
        startIndex tail.length relocations
        (transferLocalCertificateExactOfChecked cache relocationIndex
          tableRva startIndex head checked.1)
        (induction (startIndex := startIndex + 1) checked.2)

noncomputable def TransferCertificatePack.localExactCertificate
    (pack : TransferCertificatePack) (leafCapacity rangeLeafCapacity : Nat)
    (cache : ImmutableByteCache pe imports)
    (relocationIndex : RelocationRvaIndexCertificate relocations)
    (tableRva : Nat)
    (checked : pack.localChecked leafCapacity rangeLeafCapacity cache relocationIndex
      tableRva = true) :
    LayoutMExactCertificate
      (decodeManyAux (fun index => decodeTransferAt pe imports tableRva index)
        pack.startIndex pack.entries.toList.length)
      (pack.entries.toList.map TransferCertificateData.compiled) relocations := by
  rw [TransferCertificatePack.localChecked, Bool.and_eq_true,
    Bool.and_eq_true] at checked
  exact transferLocalCertificateListExact cache relocationIndex tableRva pack.startIndex
    pack.entries.toList checked.2.2

/-- A candidate-independent local certificate.  Its proof checks only the
compact layout, the records in this pack, and the immutable byte ranges named
by this pack.  Quantification over `fallback` is important: it proves that the
decoder never consulted an unlisted range, without importing the candidate PE
or trusting a generated coverage status. -/
structure TransferCertificatePack.LocalCertificate
    (layout : CandidateDataLayout) (tableRva leafCapacity rangeLeafCapacity : Nat)
    (pack : TransferCertificatePack) (cache : LocalImmutableByteCache) : Prop where
  entriesStructurallyValid :
    pack.entries.structurallyValid leafCapacity = true
  rangesStructurallyValid :
    cache.ranges.structurallyValid rangeLeafCapacity = true
  relocationQueriesLocallyValid :
    (transferCertificateDataListTrace pack.entries.toList).localFieldsValid = true
  decodedForFallback : forall fallback : Nat -> Nat -> Option Bytes,
    decodeManyAux (fun index => decodeTransferAtFrom layout.asPE
      (cache.readWith fallback) tableRva index)
      pack.startIndex pack.entries.toList.length =
        .ok (pack.entries.toList.map TransferCertificateData.compiled)
          (transferCertificateDataListTrace pack.entries.toList)

/-- Bind one local pack to the exact candidate.  All heavyweight candidate
facts are premises and therefore checked once by the generated global
authority module; the local `.olean` has no dependency on candidate bytes. -/
noncomputable def TransferCertificatePack.LocalCertificate.exactCertificate
    (certificate : TransferCertificatePack.LocalCertificate layout tableRva
      leafCapacity rangeLeafCapacity pack cache)
    (pe : PE32) (imports : List PEImport) (relocations : List BaseRelocation)
    (layoutExact : CandidateDataLayout.ofPE pe = layout)
    (rangesAuthoritative : forall range, range ∈ cache.ranges.toList ->
      immutableRvaBytes pe imports range.rva range.size = some range.bytes)
    (relocationsAuthoritative :
      (transferCertificateDataListTrace
        pack.entries.toList).relocationFieldsChecked relocations = true) :
    LayoutMExactCertificate
      (decodeManyAux (fun index => decodeTransferAt pe imports tableRva index)
        pack.startIndex pack.entries.toList.length)
      (pack.entries.toList.map TransferCertificateData.compiled) relocations := by
  let fallback := immutableRvaBytes pe imports
  have cacheExact : cache.readWith fallback = fallback :=
    cache.readWith_eq_fallback fallback rangesAuthoritative
  have localDecoded := certificate.decodedForFallback fallback
  have decoderExact :
      (fun index => decodeTransferAt pe imports tableRva index) =
        (fun index => decodeTransferAtFrom layout.asPE
          (cache.readWith fallback) tableRva index) := by
    funext index
    unfold decodeTransferAt
    rw [decodeTransferAtFrom_dataLayout, layoutExact, cacheExact]
  refine {
    trace := transferCertificateDataListTrace pack.entries.toList
    decodedExact := ?_
    relocationFields :=
      LayoutTraceRelocationCertificate.of_checked relocationsAuthoritative
  }
  rw [decoderExact]
  exact localDecoded

/-- A record-sized local proof.  Component equalities are separate fields so
Lean never has to normalize an entire generated pack in one equality. -/
structure TransferCertificateData.LocalCertificate
    (layout : CandidateDataLayout) (tableRva index : Nat)
    (data : TransferCertificateData) (cache : LocalImmutableByteCache) : Prop where
  descriptorDecoded : forall fallback : Nat -> Nat -> Option Bytes,
    decodeTransferDescriptorFrom (cache.readWith fallback) tableRva index =
      some data.descriptor
  descriptorValid :
    ((tableRva + index * transferRecordSize) % 4 == 0 &&
      data.descriptor.sourceRva < 2 ^ 32) = true
  wordNodesDecoded : forall fallback : Nat -> Nat -> Option Bytes,
    decodeNodeArrayFrom layout.asPE (cache.readWith fallback)
      (tableRva + index * transferRecordSize + 20)
      data.descriptor.wordPointer data.descriptor.wordCount
      wordNodeSize maxWordNodes = .ok data.wordNodes data.wordTrace
  x87NodesDecoded : forall fallback : Nat -> Nat -> Option Bytes,
    decodeNodeArrayFrom layout.asPE (cache.readWith fallback)
      (tableRva + index * transferRecordSize + 24)
      data.descriptor.x87Pointer data.descriptor.x87Count
      x87NodeSize maxX87Nodes = .ok data.x87Nodes data.x87Trace
  actionsDecoded : forall fallback : Nat -> Nat -> Option Bytes,
    decodeActionArrayFrom layout.asPE (cache.readWith fallback)
      (tableRva + index * transferRecordSize + 28)
      data.descriptor.actionPointer data.descriptor.actionCount =
        .ok data.actions data.actionTrace
  callsDecoded : forall fallback : Nat -> Nat -> Option Bytes,
    decodeCallArrayFrom layout.asPE (cache.readWith fallback)
      (tableRva + index * transferRecordSize + 32)
      data.descriptor.callPointer (callCountFromActions data.actions) =
        .ok data.calls data.callTrace
  x87ReplaysDecoded : forall fallback : Nat -> Nat -> Option Bytes,
    decodeX87ReplayArrayFrom layout.asPE (cache.readWith fallback)
      (tableRva + index * transferRecordSize + 36)
      data.descriptor.replayPointer data.descriptor.replayCount =
        .ok data.x87Replays data.replayTrace

theorem TransferCertificateData.LocalCertificate.decodedForFallback
    (certificate : TransferCertificateData.LocalCertificate layout tableRva
      index data cache)
    (fallback : Nat -> Nat -> Option Bytes) :
    decodeTransferAtFrom layout.asPE (cache.readWith fallback) tableRva index =
      .ok data.compiled data.trace := by
  simpa [TransferCertificateData.compiled, TransferCertificateData.trace] using
    decodeTransferAtFrom_eq_of_components layout.asPE (cache.readWith fallback)
      tableRva index data.descriptor data.wordNodes data.x87Nodes data.actions
      data.calls data.x87Replays data.wordTrace data.x87Trace data.actionTrace
      data.callTrace data.replayTrace (certificate.descriptorDecoded fallback)
      certificate.descriptorValid (certificate.wordNodesDecoded fallback)
      (certificate.x87NodesDecoded fallback) (certificate.actionsDecoded fallback)
      (certificate.callsDecoded fallback) (certificate.x87ReplaysDecoded fallback)

/-- Bind one record-sized local proof to exact PE bytes and checked
relocations.  Both authorities are supplied by later generated modules. -/
noncomputable def TransferCertificateData.LocalCertificate.exactCertificate
    (certificate : TransferCertificateData.LocalCertificate layout tableRva
      index data cache)
    (pe : PE32) (imports : List PEImport) (relocations : List BaseRelocation)
    (layoutExact : CandidateDataLayout.ofPE pe = layout)
    (rangesAuthoritative : forall range, range ∈ cache.ranges.toList ->
      immutableRvaBytes pe imports range.rva range.size = some range.bytes)
    (relocationsAuthoritative :
      data.trace.relocationFieldsChecked relocations = true) :
    LayoutMExactCertificate (decodeTransferAt pe imports tableRva index)
      data.compiled relocations := by
  let fallback := immutableRvaBytes pe imports
  have cacheExact : cache.readWith fallback = fallback :=
    cache.readWith_eq_fallback fallback rangesAuthoritative
  have localDecoded := certificate.decodedForFallback fallback
  have decoderExact :
      decodeTransferAt pe imports tableRva index =
        decodeTransferAtFrom layout.asPE (cache.readWith fallback)
          tableRva index := by
    unfold decodeTransferAt
    rw [decodeTransferAtFrom_dataLayout, layoutExact, cacheExact]
  refine {
    trace := data.trace
    decodedExact := ?_
    relocationFields :=
      LayoutTraceRelocationCertificate.of_checked relocationsAuthoritative
  }
  rw [decoderExact]
  exact localDecoded

theorem decodeManyAux_shift (decode : Nat -> LayoutM alpha)
    (start index count : Nat) :
    decodeManyAux (fun offset => decode (start + offset)) index count =
      decodeManyAux decode (start + index) count := by
  induction count generalizing index with
  | zero => rfl
  | succ count induction =>
      simp [decodeManyAux, induction, Nat.add_assoc]

theorem decodeMany_shift (decode : Nat -> LayoutM alpha) (start count : Nat) :
    decodeMany count (fun offset => decode (start + offset)) =
      decodeManyAux decode start count := by
  simpa [decodeMany] using decodeManyAux_shift decode start 0 count

theorem LayoutMExactCertificate.value?_eq
    (certificate : LayoutMExactCertificate decoded expected relocations) :
    decoded.value? = some expected := by
  rw [certificate.decodedExact]
  rfl

def LayoutTrace.relocationsChecked (trace : LayoutTrace)
    (relocations : List BaseRelocation) : Bool :=
  (relocationInventoryLinearChecked relocations &&
    relocationInventoryUnique relocations) && trace.relocationFieldsChecked relocations

theorem LayoutTrace.relocationsChecked_of_inventoryUnique
    (trace : LayoutTrace) (relocations : List BaseRelocation)
    (inventoryLinear : relocationInventoryLinearChecked relocations = true)
    (inventoryUnique : relocationInventoryUnique relocations = true)
    (fieldsChecked : trace.relocationFieldsChecked relocations = true) :
    trace.relocationsChecked relocations = true := by
  simp [LayoutTrace.relocationsChecked, inventoryLinear, inventoryUnique,
    fieldsChecked]

theorem LayoutMExactCertificate.relocationsChecked
    (certificate : LayoutMExactCertificate decoded expected relocations)
    (inventoryLinear : relocationInventoryLinearChecked relocations = true)
    (inventoryUnique : relocationInventoryUnique relocations = true) :
    (match decoded.trace? with
    | none => false
    | some trace => trace.relocationsChecked relocations) = true := by
  rw [certificate.decodedExact]
  exact LayoutTrace.relocationsChecked_of_inventoryUnique certificate.trace
    relocations inventoryLinear inventoryUnique
    certificate.relocationFields.checked

/-- Compose adjacent successful PE base-relocation entry parses. -/
theorem parseRelocationEntries_append_of_checked
    (pe : PE32) (pageRva entriesRva prefixCount suffixCount : Nat)
    (firstEntries secondEntries : List BaseRelocation)
    (prefixParsed :
      parseRelocationEntries pe pageRva entriesRva prefixCount =
        some firstEntries)
    (suffixParsed :
      parseRelocationEntries pe pageRva (entriesRva + 2 * prefixCount)
        suffixCount = some secondEntries) :
    parseRelocationEntries pe pageRva entriesRva (prefixCount + suffixCount) =
      some (firstEntries ++ secondEntries) := by
  induction prefixCount generalizing entriesRva firstEntries with
  | zero =>
      simp only [parseRelocationEntries] at prefixParsed
      have prefixEmpty : [] = firstEntries := by
        exact Option.some.inj prefixParsed
      subst firstEntries
      simpa using suffixParsed
  | succ count ih =>
      cases entryRead : readRvaU16 pe entriesRva with
      | none =>
          simp [parseRelocationEntries, entryRead] at prefixParsed
      | some value =>
          cases tailParsed :
              parseRelocationEntries pe pageRva (entriesRva + 2) count with
          | none =>
              simp [parseRelocationEntries, entryRead, tailParsed] at prefixParsed
          | some tail =>
              have suffixParsed' :
                  parseRelocationEntries pe pageRva
                    (entriesRva + 2 + 2 * count) suffixCount =
                      some secondEntries := by
                simpa [Nat.mul_succ, Nat.add_assoc, Nat.add_comm,
                  Nat.add_left_comm] using suffixParsed
              have tailAppended := ih (entriesRva := entriesRva + 2)
                (firstEntries := tail) tailParsed suffixParsed'
              by_cases padding : value < 4096
              · have prefixEq : tail = firstEntries := by
                  simpa [parseRelocationEntries, entryRead, tailParsed, padding]
                    using prefixParsed
                subst firstEntries
                simpa [Nat.succ_add, parseRelocationEntries, entryRead, padding]
                  using tailAppended
              · by_cases highlow : value / 4096 = 3
                · have prefixEq :
                      { rva := pageRva + value % 4096, kind := value / 4096 } ::
                          tail = firstEntries := by
                    simpa [parseRelocationEntries, entryRead, tailParsed, padding,
                      highlow] using prefixParsed
                  subst firstEntries
                  simp [Nat.succ_add, parseRelocationEntries, entryRead,
                    padding, highlow, tailAppended]
                · simp [parseRelocationEntries, entryRead, tailParsed, padding,
                    highlow] at prefixParsed

/-- Compose one exact PE base-relocation block with an already checked suffix.
Generated proofs use this theorem as a cache boundary: decoding the entries of
one block never re-evaluates the remaining relocation directory. -/
theorem parseRelocationBlocks_cons_of_checked
    (pe : PE32) (offset fuel pageRva blockSize : Nat)
    (entries tail : List BaseRelocation)
    (notEnd : (offset == pe.relocationDirectorySize) = false)
    (headerFits : (offset + 8 > pe.relocationDirectorySize) = false)
    (pageRead : readRvaU32 pe (pe.relocationDirectoryRva + offset) =
      some pageRva)
    (sizeRead : readRvaU32 pe (pe.relocationDirectoryRva + offset + 4) =
      some blockSize)
    (shapeValid :
      (blockSize < 8 || blockSize % 2 != 0 ||
        offset + blockSize > pe.relocationDirectorySize) = false)
    (entriesParsed :
      parseRelocationEntries pe pageRva
        (pe.relocationDirectoryRva + offset + 8) ((blockSize - 8) / 2) =
          some entries)
    (tailParsed : parseRelocationBlocks pe (offset + blockSize) fuel =
      some tail) :
    parseRelocationBlocks pe offset (fuel + 1) = some (entries ++ tail) := by
  simp only [parseRelocationBlocks, notEnd, headerFits, pageRead, sizeRead,
    shapeValid, entriesParsed, tailParsed, Option.bind_eq_bind,
    Option.bind_some]
  simp

structure ProgramTableShardCertificate (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva : Nat) where
  startIndex : Nat
  entries : List CompiledProgramRecord
  nonempty : entries.isEmpty = false
  decoded :
    (decodeProgramTableRange pe imports tableRva startIndex entries.length).value? =
      some entries
  relocationFieldsChecked :
    (match (decodeProgramTableRange pe imports tableRva startIndex entries.length).trace? with
    | none => false
    | some trace => trace.relocationsChecked relocations) = true

def ProgramTableShardCertificate.records
    (certificate : ProgramTableShardCertificate pe imports relocations tableRva) :
    List ProgramRecord :=
  certificate.entries.map (fun entry => entry.record)

/-- Compact metadata for one exact decoded shard.  Generated authority leaves
prove these three fields beside the shard, where projecting source RVAs from
the local semantic records is bounded work.  Global composition then consumes
only this metadata and never re-normalizes the complete program table. -/
structure ProgramTableShardMetadataCertificate
    (shard : ProgramTableShardCertificate pe imports relocations tableRva)
    (expectedStart expectedCount : Nat) (sourceRvas : List Nat) : Prop where
  startIndexExact : shard.startIndex = expectedStart
  entryCountExact : shard.entries.length = expectedCount
  sourceRvasExact :
    shard.records.map (fun record => record.sourceRva) = sourceRvas

def shardCoverageEnd (cursor : Nat) :
    List (ProgramTableShardCertificate pe imports relocations tableRva) -> Option Nat
  | [] => some cursor
  | shard :: tail =>
      if shard.startIndex != cursor || shard.entries.isEmpty then none else
      shardCoverageEnd (cursor + shard.entries.length) tail

def decodedShardRecords
    (shards : List (ProgramTableShardCertificate pe imports relocations tableRva)) :
    List ProgramRecord :=
  shards.flatMap ProgramTableShardCertificate.records

/-- Compose one locally checked shard shape with an already checked suffix.
The proof uses only metadata equalities and the shard's existing nonempty
field; semantic record bodies stay opaque. -/
theorem ProgramTableShardMetadataCertificate.coverage_cons
    {shard : ProgramTableShardCertificate pe imports relocations tableRva}
    {expectedStart expectedCount result : Nat} {sourceRvas : List Nat}
    (metadata : ProgramTableShardMetadataCertificate shard
      expectedStart expectedCount sourceRvas)
    (tail : List
      (ProgramTableShardCertificate pe imports relocations tableRva))
    (tailCovered :
      shardCoverageEnd (expectedStart + expectedCount) tail = some result) :
    shardCoverageEnd expectedStart (shard :: tail) = some result := by
  simp only [shardCoverageEnd]
  rw [metadata.startIndexExact, metadata.entryCountExact]
  simp [shard.nonempty, tailCovered]

/-- Compose the exact source-RVA projection without unfolding either the
current shard's semantic values or any previously checked suffix. -/
theorem ProgramTableShardMetadataCertificate.sourceRvas_cons
    {shard : ProgramTableShardCertificate pe imports relocations tableRva}
    {expectedStart expectedCount : Nat} {sourceRvas tailSourceRvas : List Nat}
    (metadata : ProgramTableShardMetadataCertificate shard
      expectedStart expectedCount sourceRvas)
    (tail : List
      (ProgramTableShardCertificate pe imports relocations tableRva))
    (tailExact :
      (decodedShardRecords tail).map (fun record => record.sourceRva) =
        tailSourceRvas) :
    (decodedShardRecords (shard :: tail)).map
        (fun record => record.sourceRva) =
      sourceRvas ++ tailSourceRvas := by
  simp only [decodedShardRecords, List.flatMap_cons, List.map_append]
  have tailExact' :
      (List.flatMap ProgramTableShardCertificate.records tail).map
          (fun record => record.sourceRva) = tailSourceRvas := by
    simpa only [decodedShardRecords] using tailExact
  rw [metadata.sourceRvasExact, tailExact']

/-- A compositional inventory of adjacent table shards.  Its indices expose
the complete start/count chain and source-RVA inventory without introducing a
second status field that generated code could assert independently. -/
inductive ProgramTableShardMetadataChain
    (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva : Nat) :
    Nat ->
    List (ProgramTableShardCertificate pe imports relocations tableRva) ->
    List Nat -> Nat -> Prop where
  | nil (cursor : Nat) :
      ProgramTableShardMetadataChain pe imports relocations tableRva
        cursor [] [] cursor
  | cons
      {shard : ProgramTableShardCertificate pe imports relocations tableRva}
      {start count : Nat} {sourceRvas : List Nat}
      {tail : List
        (ProgramTableShardCertificate pe imports relocations tableRva)}
      {tailSourceRvas : List Nat} {endCursor : Nat}
      (head : ProgramTableShardMetadataCertificate shard
        start count sourceRvas)
      (rest : ProgramTableShardMetadataChain pe imports relocations tableRva
        (start + count) tail tailSourceRvas endCursor) :
      ProgramTableShardMetadataChain pe imports relocations tableRva
        start (shard :: tail) (sourceRvas ++ tailSourceRvas) endCursor

theorem ProgramTableShardMetadataChain.coverage
    (chain : ProgramTableShardMetadataChain pe imports relocations tableRva
      start shards sourceRvas endCursor) :
    shardCoverageEnd start shards = some endCursor := by
  induction chain with
  | nil => rfl
  | cons head rest induction =>
      exact head.coverage_cons _ induction

theorem ProgramTableShardMetadataChain.sourceRvasExact
    (chain : ProgramTableShardMetadataChain pe imports relocations tableRva
      start shards sourceRvas endCursor) :
    (decodedShardRecords shards).map (fun record => record.sourceRva) =
      sourceRvas := by
  induction chain with
  | nil => rfl
  | cons head rest induction =>
      exact head.sourceRvas_cons _ induction

structure ProgramTableCertificate (pe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva countRva : Nat)
    (semanticRecords : List ProgramRecord) where
  transferCount : Nat
  countDecoded : readCompiledTransferCount pe imports countRva = some transferCount
  relocationsParsed : parseRelocations pe = some relocations
  shards : List (ProgramTableShardCertificate pe imports relocations tableRva)
  shardsCover : shardCoverageEnd (pe := pe) (imports := imports)
    (relocations := relocations) (tableRva := tableRva) 0 shards = some transferCount
  semanticRecordsExact : semanticRecords = decodedShardRecords shards
  sourceRvasUnique :
    (semanticRecords.map (fun record => record.sourceRva)).Nodup

theorem ProgramTableCertificate.lookup_agrees
    (certificate : ProgramTableCertificate pe imports relocations
      tableRva countRva semanticRecords) (sourceRva : Nat) :
    lookupProgramRecord (decodedShardRecords certificate.shards) sourceRva =
      lookupProgramRecord semanticRecords sourceRva := by
  exact (congrArg (fun records => lookupProgramRecord records sourceRva)
    certificate.semanticRecordsExact).symm

/-- No record can enter the abstract lookup without an exact PE-backed shard
decode.  The theorem is intentionally phrased over the same lookup function
used by the semantic interpreter kernel. -/
theorem ProgramTableCertificate.semantic_lookup_is_compiled_lookup
    (certificate : ProgramTableCertificate pe imports relocations
      tableRva countRva semanticRecords) (sourceRva : Nat) :
    lookupProgramRecord semanticRecords sourceRva =
      lookupProgramRecord (decodedShardRecords certificate.shards) sourceRva :=
  (certificate.lookup_agrees sourceRva).symm

end StageA.Relational.InterpreterKernelData
