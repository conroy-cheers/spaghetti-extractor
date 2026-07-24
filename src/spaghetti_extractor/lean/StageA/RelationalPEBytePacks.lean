import StageA.RelationalLoader

namespace StageA.Relational.PEBytePacks

open StageA.Formal

/-- A structural path from an authoritative byte tree to an exact subtree.
The node-size equations used by `left` and `right` make construction fail
closed for malformed cached tree metadata. -/
structure ByteTreePackAt (tree : ByteTree) (rawOffset : Nat)
    (pack : ByteTree) : Prop where
  rawEndBounded : rawOffset + pack.length <= tree.length
  readByteExact : forall offset, offset < pack.length ->
    tree.readByte (rawOffset + offset) = pack.readByte offset

def ByteTreePackAt.here (tree : ByteTree) : ByteTreePackAt tree 0 tree := {
  rawEndBounded := by simp
  readByteExact := by simp
}

def ByteTreePackAt.left
    {size cachedLeftSize rawOffset : Nat} {left right pack : ByteTree}
    (nodeSize : size = left.length + right.length)
    (leftSize : cachedLeftSize = left.length)
    (located : ByteTreePackAt left rawOffset pack) :
    ByteTreePackAt (.node size cachedLeftSize left right) rawOffset pack := {
  rawEndBounded := by
    have bound := located.rawEndBounded
    change rawOffset + pack.length <= size
    rw [nodeSize]
    omega
  readByteExact := by
    intro offset inside
    simp only [ByteTree.readByte]
    rw [nodeSize, leftSize]
    rw [if_neg (by
      have bound := located.rawEndBounded
      omega)]
    rw [if_pos (by
      have bound := located.rawEndBounded
      omega)]
    exact located.readByteExact offset inside
}

def ByteTreePackAt.right
    {size cachedLeftSize rawOffset : Nat} {left right pack : ByteTree}
    (nodeSize : size = left.length + right.length)
    (leftSize : cachedLeftSize = left.length)
    (located : ByteTreePackAt right rawOffset pack) :
    ByteTreePackAt (.node size cachedLeftSize left right)
      (left.length + rawOffset) pack := {
  rawEndBounded := by
    have bound := located.rawEndBounded
    change left.length + rawOffset + pack.length <= size
    rw [nodeSize]
    omega
  readByteExact := by
    intro offset inside
    simp only [ByteTree.readByte]
    rw [nodeSize, leftSize]
    rw [if_neg (by
      have bound := located.rawEndBounded
      omega)]
    rw [if_neg (by omega)]
    rw [show left.length + rawOffset + offset - left.length =
      rawOffset + offset by omega]
    exact located.readByteExact offset inside
}

theorem ByteTreePackAt.raw_end_le {tree pack : ByteTree} {rawOffset : Nat}
    (located : ByteTreePackAt tree rawOffset pack) :
    rawOffset + pack.length <= tree.length :=
  located.rawEndBounded

theorem ByteTreePackAt.readByte_eq {tree pack : ByteTree} {rawOffset : Nat}
    (located : ByteTreePackAt tree rawOffset pack) (offset : Nat)
    (inside : offset < pack.length) :
    tree.readByte (rawOffset + offset) = pack.readByte offset :=
  located.readByteExact offset inside

theorem ByteTreePackAt.readBytes_eq {tree pack : ByteTree} {rawOffset : Nat}
    (located : ByteTreePackAt tree rawOffset pack) (offset size : Nat)
    (inside : offset + size <= pack.length) :
    tree.readBytes (rawOffset + offset) size = pack.readBytes offset size := by
  induction size generalizing offset with
  | zero => simp [ByteTree.readBytes]
  | succ size induction =>
      simp only [ByteTree.readBytes]
      rw [located.readByte_eq offset (by omega)]
      have tail := induction (offset + 1) (by omega)
      rw [show rawOffset + offset + 1 = rawOffset + (offset + 1) by omega]
      rw [tail]

/-- One independently cacheable exact subtree of an authoritative PE byte
tree. Consumers trust only the kernel-checked structural path. -/
structure PEBytePackCertificate (pe : PE32) where
  rawOffset : Nat
  pack : ByteTree
  nonempty : 0 < pack.length
  valid : pe32ByteTreeValid pack = true
  located : ByteTreePackAt pe.bytes rawOffset pack

def PEBytePackCertificate.rawEnd {pe : PE32}
    (certificate : PEBytePackCertificate pe) : Nat :=
  certificate.rawOffset + certificate.pack.length

theorem PEBytePackCertificate.raw_end_le {pe : PE32}
    (certificate : PEBytePackCertificate pe) :
    certificate.rawEnd <= pe.bytes.length :=
  certificate.located.raw_end_le

theorem PEBytePackCertificate.readBytes_eq {pe : PE32}
    (certificate : PEBytePackCertificate pe) (offset size : Nat)
    (inside : offset + size <= certificate.pack.length) :
    pe.bytes.readBytes (certificate.rawOffset + offset) size =
      certificate.pack.readBytes offset size :=
  certificate.located.readBytes_eq offset size inside

/-- A bounded local view into a checked pack. Its result reduces only the local
pack tree, never the authoritative PE tree. -/
structure PEBytePackSlice (pe : PE32) where
  certificate : PEBytePackCertificate pe
  offset : Nat
  size : Nat
  nonempty : 0 < size
  bounded : offset + size <= certificate.pack.length

def PEBytePackSlice.rawOffset {pe : PE32} (slice : PEBytePackSlice pe) : Nat :=
  slice.certificate.rawOffset + slice.offset

def PEBytePackSlice.bytes {pe : PE32} (slice : PEBytePackSlice pe) : Option Bytes :=
  slice.certificate.pack.readBytes slice.offset slice.size

theorem PEBytePackSlice.readBytes_eq {pe : PE32}
    (slice : PEBytePackSlice pe) :
    pe.bytes.readBytes slice.rawOffset slice.size = slice.bytes :=
  slice.certificate.readBytes_eq slice.offset slice.size slice.bounded

theorem ByteTree.readBytes_add (tree : ByteTree) (rawOffset leftSize rightSize : Nat) :
    tree.readBytes rawOffset (leftSize + rightSize) = (do
      let left <- tree.readBytes rawOffset leftSize
      let right <- tree.readBytes (rawOffset + leftSize) rightSize
      pure (left ++ right)) := by
  induction leftSize generalizing rawOffset with
  | zero => simp [ByteTree.readBytes]
  | succ leftSize induction =>
      simp only [Nat.succ_add, ByteTree.readBytes]
      cases headRead : tree.readByte rawOffset with
      | none => simp
      | some head =>
          rw [induction (rawOffset + 1)]
          cases leftRead : tree.readBytes (rawOffset + 1) leftSize with
          | none => simp
          | some left =>
              rw [show rawOffset + 1 + leftSize =
                rawOffset + (leftSize + 1) by omega]
              cases rightRead : tree.readBytes (rawOffset + (leftSize + 1))
                  rightSize with
              | none => simp
              | some right => simp

def readPEBytePackSlices {pe : PE32} : List (PEBytePackSlice pe) -> Option Bytes
  | [] => some []
  | slice :: slices => do
      let head <- slice.bytes
      let tail <- readPEBytePackSlices slices
      pure (head ++ tail)

/-- A chain is exact only when every nonempty slice starts where the previous
slice stopped. This supports a span crossing any number of adjacent packs. -/
inductive PEBytePackSliceChain (pe : PE32) :
    Nat -> Nat -> List (PEBytePackSlice pe) -> Prop where
  | nil (rawOffset : Nat) : PEBytePackSliceChain pe rawOffset 0 []
  | cons (slice : PEBytePackSlice pe)
      (starts : slice.rawOffset = rawOffset)
      (tail : PEBytePackSliceChain pe (rawOffset + slice.size) tailSize slices) :
      PEBytePackSliceChain pe rawOffset (slice.size + tailSize) (slice :: slices)

theorem PEBytePackSliceChain.readBytes_eq {pe : PE32} {rawOffset size : Nat}
    {slices : List (PEBytePackSlice pe)}
    (chain : PEBytePackSliceChain pe rawOffset size slices) :
    pe.bytes.readBytes rawOffset size = readPEBytePackSlices slices := by
  induction chain with
  | nil => simp [ByteTree.readBytes, readPEBytePackSlices]
  | cons slice starts tail induction =>
      rw [ByteTree.readBytes_add]
      rw [starts.symm, slice.readBytes_eq]
      rw [starts, induction]
      rfl

def sectionContainsExactRvaSpan (sec : Section) (rva size : Nat) : Bool :=
  sec.virtualAddress <= rva &&
    size <= sec.virtualAddress + sec.mappedSize - rva

/-- A span reader equivalent to the direct section branch of `exactRvaSpan`.
It reads one contiguous raw range after rejecting headers, virtual zero-fill,
out-of-image spans, and ambiguous section mappings. -/
def readExactSectionRvaSpan (pe : PE32) (rva size : Nat) : Option Bytes := do
  if !exactRvaSpan pe rva size then none else
  if rva < pe.sizeOfHeaders then none else
  match pe.sections.filter (fun sec =>
      sectionContainsExactRvaSpan sec rva size) with
  | [sec] =>
      pe.bytes.readBytes
        (sec.rawPointer + (rva - sec.virtualAddress)) size
  | _ => none

/-- Small, metadata-only evidence that one exact RVA span maps uniquely to a
bounded raw-file range. -/
structure PESectionRvaSpanCertificate (pe : PE32) (sec : Section)
    (rva size rawOffset : Nat) : Prop where
  nonempty : Not (size = 0)
  imageStartBounded : rva <= pe.sizeOfImage
  imageSizeBounded : size <= pe.sizeOfImage - rva
  afterHeaders : pe.sizeOfHeaders <= rva
  uniqueSection :
    pe.sections.filter (fun candidate =>
      sectionContainsExactRvaSpan candidate rva size) = [sec]
  virtualStartBounded : sec.virtualAddress <= rva
  rawStartBounded : rva - sec.virtualAddress <= sec.rawSize
  rawSizeBounded :
    size <= sec.rawSize - (rva - sec.virtualAddress)
  rawOffsetExact :
    rawOffset = sec.rawPointer + (rva - sec.virtualAddress)
  fileStartBounded : rawOffset <= pe.bytes.length
  fileSizeBounded : size <= pe.bytes.length - rawOffset

/-- Boolean reflection used by generated schedule modules. It checks only PE
metadata and arithmetic; exact bytes come from a separately cached pack. -/
def PESectionRvaSpanCertificate.checked (pe : PE32) (sec : Section)
    (rva size rawOffset : Nat) : Bool :=
  size != 0 && (
    rva <= pe.sizeOfImage && (
    size <= pe.sizeOfImage - rva && (
    pe.sizeOfHeaders <= rva && (
    pe.sections.filter (fun candidate =>
      sectionContainsExactRvaSpan candidate rva size) == [sec] && (
    sec.virtualAddress <= rva && (
    rva - sec.virtualAddress <= sec.rawSize && (
    size <= sec.rawSize - (rva - sec.virtualAddress) && (
    rawOffset == sec.rawPointer + (rva - sec.virtualAddress) && (
    rawOffset <= pe.bytes.length &&
    size <= pe.bytes.length - rawOffset)))))))))

theorem PESectionRvaSpanCertificate.of_checked (pe : PE32) (sec : Section)
    (rva size rawOffset : Nat)
    (checked : PESectionRvaSpanCertificate.checked pe sec rva size rawOffset = true) :
    PESectionRvaSpanCertificate pe sec rva size rawOffset := by
  simp only [PESectionRvaSpanCertificate.checked, Bool.and_eq_true,
    bne_iff_ne, decide_eq_true_eq, beq_iff_eq] at checked
  exact {
    nonempty := checked.1
    imageStartBounded := checked.2.1
    imageSizeBounded := checked.2.2.1
    afterHeaders := checked.2.2.2.1
    uniqueSection := checked.2.2.2.2.1
    virtualStartBounded := checked.2.2.2.2.2.1
    rawStartBounded := checked.2.2.2.2.2.2.1
    rawSizeBounded := checked.2.2.2.2.2.2.2.1
    rawOffsetExact := checked.2.2.2.2.2.2.2.2.1
    fileStartBounded := checked.2.2.2.2.2.2.2.2.2.1
    fileSizeBounded := checked.2.2.2.2.2.2.2.2.2.2
  }

theorem PESectionRvaSpanCertificate.exactRvaSpan_eq_true {pe : PE32}
    {sec : Section} {rva size rawOffset : Nat}
    (certificate : PESectionRvaSpanCertificate pe sec rva size rawOffset) :
    exactRvaSpan pe rva size = true := by
  have imageStartBounded := certificate.imageStartBounded
  have imageSizeBounded := certificate.imageSizeBounded
  have afterHeaders := certificate.afterHeaders
  unfold exactRvaSpan
  rw [if_neg (by
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or]
    constructor <;> omega)]
  rw [if_neg (by simpa [beq_iff_eq] using certificate.nonempty)]
  rw [if_neg (by omega)]
  rw [show pe.sections.filter (fun candidate =>
      candidate.virtualAddress <= rva &&
        size <= candidate.virtualAddress + candidate.mappedSize - rva) =
      [sec] by simpa [sectionContainsExactRvaSpan] using certificate.uniqueSection]
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  exact ⟨⟨⟨certificate.rawStartBounded, certificate.rawSizeBounded⟩,
    by
      rw [certificate.rawOffsetExact.symm]
      exact certificate.fileStartBounded⟩,
    by
      rw [certificate.rawOffsetExact.symm]
      exact certificate.fileSizeBounded⟩

theorem PESectionRvaSpanCertificate.read_eq_raw {pe : PE32}
    {sec : Section} {rva size rawOffset : Nat}
    (certificate : PESectionRvaSpanCertificate pe sec rva size rawOffset) :
    readExactSectionRvaSpan pe rva size =
      pe.bytes.readBytes rawOffset size := by
  have afterHeaders := certificate.afterHeaders
  unfold readExactSectionRvaSpan
  rw [certificate.exactRvaSpan_eq_true]
  simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
  rw [if_neg (by omega)]
  rw [show pe.sections.filter (fun candidate =>
      sectionContainsExactRvaSpan candidate rva size) = [sec] from
      certificate.uniqueSection]
  simp [certificate.rawOffsetExact]

/-- Kernel bridge for the common case: one checked pack and one metadata-only
section check derive exact RVA bytes without reducing the authoritative PE. -/
theorem readExactSectionRvaSpan_eq_pack_of_checked {pe : PE32}
    (pack : PEBytePackCertificate pe) (sec : Section)
    (rva size offset : Nat)
    (inside : offset + size <= pack.pack.length)
    (checked : PESectionRvaSpanCertificate.checked pe sec rva size
      (pack.rawOffset + offset) = true) :
    readExactSectionRvaSpan pe rva size = pack.pack.readBytes offset size := by
  let mapping := PESectionRvaSpanCertificate.of_checked pe sec rva size
    (pack.rawOffset + offset) checked
  rw [mapping.read_eq_raw]
  exact pack.readBytes_eq offset size inside

/-- Kernel bridge for a span split across adjacent pack slices. -/
theorem readExactSectionRvaSpan_eq_slices_of_checked {pe : PE32}
    (sec : Section) (rva size rawOffset : Nat)
    (slices : List (PEBytePackSlice pe))
    (chain : PEBytePackSliceChain pe rawOffset size slices)
    (checked : PESectionRvaSpanCertificate.checked pe sec rva size rawOffset = true) :
    readExactSectionRvaSpan pe rva size = readPEBytePackSlices slices := by
  let mapping := PESectionRvaSpanCertificate.of_checked pe sec rva size
    rawOffset checked
  rw [mapping.read_eq_raw]
  exact chain.readBytes_eq

end StageA.Relational.PEBytePacks
