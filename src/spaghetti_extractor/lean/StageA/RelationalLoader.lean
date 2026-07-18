import StageA.Formal

namespace StageA.Relational

open StageA.Formal

def pe32AddressSpaceSize : Nat := 2 ^ 32

/-- Stage A currently models only the image recorded in the PE32 optional
header.  Any future non-preferred load mode must add its own checked policy. -/
structure PE32LoaderPolicy where
  preferredBaseOnly : Bool
deriving Repr, DecidableEq

def preferredBaseOnlyLoaderPolicy : PE32LoaderPolicy := {
  preferredBaseOnly := true
}

structure PE32CheckedHeader where
  optionalSize : Nat
  numberOfRvaAndSizes : Nat
  sectionTableOffset : Nat
  sectionTableEnd : Nat
deriving Repr, DecidableEq

def pe32PowerOfTwo (value : Nat) : Bool :=
  value != 0 && (value &&& (value - 1)) == 0

def pe32SpanBounded (start size : Nat) : Bool :=
  start <= pe32AddressSpaceSize && size <= pe32AddressSpaceSize - start

def pe32ByteTreeValid : ByteTree -> Bool
  | .empty => true
  | .leaf bytes => bytes.all (fun byte => byte < 256)
  | .node size leftSize left right =>
      pe32ByteTreeValid left && pe32ByteTreeValid right &&
        leftSize == left.length && size == left.length + right.length

theorem pe32ByteTreeValid_readByte_lt (tree : ByteTree)
    (valid : pe32ByteTreeValid tree = true) {offset byte : Nat}
    (read : tree.readByte offset = some byte) : byte < 256 := by
  induction tree generalizing offset with
  | empty => simp [ByteTree.readByte] at read
  | leaf bytes =>
    have member := List.mem_of_getElem? read
    simpa using List.all_eq_true.mp valid byte member
  | node size leftSize left right leftInduction rightInduction =>
    simp only [ByteTree.readByte] at read
    split at read
    · simp at read
    · split at read
      · exact leftInduction (by simp_all [pe32ByteTreeValid]) read
      · exact rightInduction (by simp_all [pe32ByteTreeValid]) read

theorem pe32ByteTreeValid_readByte_isSome (tree : ByteTree)
    (valid : pe32ByteTreeValid tree = true) {offset : Nat}
    (inside : offset < tree.length) :
    (tree.readByte offset).isSome = true := by
  induction tree generalizing offset with
  | empty => simp [ByteTree.length] at inside
  | leaf bytes =>
      simpa [ByteTree.readByte, ByteTree.length, inside]
  | node size leftSize left right leftInduction rightInduction =>
      simp only [pe32ByteTreeValid, Bool.and_eq_true, beq_iff_eq] at valid
      rcases valid with
        ⟨⟨⟨leftValid, rightValid⟩, leftSizeEq⟩, sizeEq⟩
      subst size
      rw [leftSizeEq]
      change offset < left.length + right.length at inside
      change (if offset >= left.length + right.length then none
        else if offset < left.length then left.readByte offset
        else right.readByte (offset - left.length)).isSome = true
      rw [if_neg (by omega)]
      by_cases inLeft : offset < left.length
      · rw [if_pos inLeft]
        exact leftInduction leftValid inLeft
      · rw [if_neg inLeft]
        exact rightInduction rightValid (by omega)

theorem pe32ByteTreeValid_rvaByte_lt (pe : PE32)
    (valid : pe32ByteTreeValid pe.bytes = true) {rva byte : Nat}
    (read : rvaByte pe rva = some byte) : byte < 256 := by
  unfold rvaByte at read
  split at read
  · exact pe32ByteTreeValid_readByte_lt pe.bytes valid read
  · cases sectionResult : pe.sections.find? (fun sec =>
        sec.virtualAddress <= rva && rva < sec.virtualAddress + sec.mappedSize) with
    | none => simp [sectionResult] at read
    | some sec =>
      simp only [sectionResult] at read
      change (if rva - sec.virtualAddress < sec.rawSize then
          pe.bytes.readByte (sec.rawPointer + (rva - sec.virtualAddress))
        else some 0) = some byte at read
      split at read
      · exact pe32ByteTreeValid_readByte_lt pe.bytes valid read
      · have byteZero : byte = 0 := Option.some.inj read.symm
        omega

def pe32AlignUp (value alignment : Nat) : Option Nat := do
  if alignment == 0 then none else
  let remainder := value % alignment
  let padding := if remainder == 0 then 0 else alignment - remainder
  if !pe32SpanBounded value padding then none else
  pure (value + padding)

def readPE32CheckedHeader (pe : PE32) : Option PE32CheckedHeader := do
  let exactPeOffset <- readTreeU32 pe.bytes 0x3c
  if exactPeOffset != pe.peOffset then none else
  let sectionCount <- readTreeU16 pe.bytes (pe.peOffset + 6)
  if sectionCount == 0 || sectionCount != pe.sections.length then none else
  let optionalSize <- readTreeU16 pe.bytes (pe.peOffset + 20)
  if optionalSize < 224 then none else
  let optionalOffset := pe.peOffset + 24
  let numberOfRvaAndSizes <- readTreeU32 pe.bytes (optionalOffset + 92)
  if numberOfRvaAndSizes > 16 ||
      numberOfRvaAndSizes > (optionalSize - 96) / 8 then none else
  let sectionTableOffset := optionalOffset + optionalSize
  let sectionTableSize := sectionCount * 40
  if !pe32SpanBounded pe.peOffset 24 ||
      !pe32SpanBounded optionalOffset optionalSize ||
      sectionCount > pe32AddressSpaceSize / 40 ||
      !pe32SpanBounded sectionTableOffset sectionTableSize then none else
  let sectionTableEnd := sectionTableOffset + sectionTableSize
  if sectionTableEnd > pe.bytes.length then none else
  pure { optionalSize, numberOfRvaAndSizes, sectionTableOffset, sectionTableEnd }

def pe32MappedSpanValid (pe : PE32) (rva size : Nat) : Bool :=
  size > 0 && pe32SpanBounded rva size && rva + size <= pe.sizeOfImage &&
    ((rva < pe.sizeOfHeaders && rva + size <= pe.sizeOfHeaders) ||
      (pe.sections.filter fun sec =>
        sec.virtualAddress <= rva &&
          rva + size <= sec.virtualAddress + sec.mappedSize).length == 1)

theorem pe32MappedSpanValid_image_bounded (pe : PE32) (rva size : Nat)
    (valid : pe32MappedSpanValid pe rva size = true) :
    rva + size <= pe.sizeOfImage := by
  unfold pe32MappedSpanValid at valid
  simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq,
    beq_iff_eq] at valid
  exact valid.1.2

def pe32DirectorySlotValid (pe : PE32) (header : PE32CheckedHeader)
    (index expectedRva expectedSize : Nat) : Bool :=
  let optionalOffset := pe.peOffset + 24
  let directoryOffset := optionalOffset + 96 + index * 8
  readTreeU32 pe.bytes directoryOffset == some expectedRva &&
    readTreeU32 pe.bytes (directoryOffset + 4) == some expectedSize &&
    if index < header.numberOfRvaAndSizes then
      (expectedRva == 0 && expectedSize == 0) ||
        (expectedRva != 0 && expectedSize != 0 &&
          pe32MappedSpanValid pe expectedRva expectedSize)
    else
      expectedRva == 0 && expectedSize == 0

def pe32SectionListValid (pe : PE32) : Nat -> Nat -> List Section -> Bool
  | mappedCursor, _rawCursor, [] =>
      pe32AlignUp mappedCursor pe.sectionAlignment == some pe.sizeOfImage
  | mappedCursor, rawCursor, sec :: sections =>
      let mappedSize := sec.mappedSize
      let mappedEnd := sec.virtualAddress + mappedSize
      let rawEnd := sec.rawPointer + sec.rawSize
      mappedSize > 0 &&
        sec.virtualAddress % pe.sectionAlignment == 0 &&
        mappedCursor <= sec.virtualAddress &&
        pe32SpanBounded sec.virtualAddress mappedSize &&
        mappedEnd <= pe.sizeOfImage &&
        (if sec.rawSize == 0 then
          sec.rawPointer == 0 &&
            pe32SectionListValid pe mappedEnd rawCursor sections
        else
          sec.rawSize % pe.fileAlignment == 0 &&
            sec.rawPointer % pe.fileAlignment == 0 &&
            rawCursor <= sec.rawPointer &&
            pe32SpanBounded sec.rawPointer sec.rawSize &&
            rawEnd <= pe.bytes.length &&
            pe32SectionListValid pe mappedEnd rawEnd sections)

theorem pe32SectionListValid_raw_bounded (pe : PE32) :
    ∀ mappedCursor rawCursor sections,
      pe32SectionListValid pe mappedCursor rawCursor sections = true ->
      ∀ sec, sec ∈ sections ->
        sec.rawPointer + sec.rawSize <= pe.bytes.length := by
  intro mappedCursor rawCursor sections
  induction sections generalizing mappedCursor rawCursor with
  | nil => simp
  | cons head tail induction =>
      intro valid sec member
      simp only [pe32SectionListValid] at valid
      simp only [List.mem_cons] at member
      rcases member with rfl | member
      · by_cases rawZero : sec.rawSize = 0 <;>
          simp_all [rawZero, Bool.and_eq_true]
      · by_cases rawZero : head.rawSize = 0
        · simp only [rawZero, beq_self_eq_true, if_true, Bool.and_eq_true,
            decide_eq_true_eq] at valid
          exact induction (head.virtualAddress + head.mappedSize) rawCursor
            valid.2.2 sec member
        · simp only [beq_iff_eq, rawZero, if_false, Bool.and_eq_true,
            decide_eq_true_eq] at valid
          exact induction (head.virtualAddress + head.mappedSize)
            (head.rawPointer + head.rawSize) valid.2.2 sec member

def pe32HeaderAndImageSizesValid (pe : PE32)
    (header : PE32CheckedHeader) : Bool :=
  match pe32AlignUp header.sectionTableEnd pe.fileAlignment with
  | none => false
  | some minimumHeaders =>
      minimumHeaders <= pe.sizeOfHeaders &&
        pe.sizeOfHeaders % pe.fileAlignment == 0 &&
        pe.sizeOfHeaders <= pe.bytes.length &&
        pe.sizeOfHeaders <= pe.sizeOfImage &&
        pe32SectionListValid pe pe.sizeOfHeaders pe.sizeOfHeaders pe.sections

def pe32EntrypointValid (pe : PE32) : Bool :=
  pe.entrypointRva == 0 ||
    (pe.entrypointRva < pe.sizeOfImage &&
      (pe.sections.filter fun sec =>
        sec.executable && sec.virtualAddress <= pe.entrypointRva &&
          pe.entrypointRva < sec.virtualAddress + sec.mappedSize).length == 1)

/-- A bounded, fail-closed PE32 loader check.  It validates the parsed value
against the exact bytes and admits only loading at the preferred image base. -/
def pe32LoaderImageValid (policy : PE32LoaderPolicy) (pe : PE32) : Bool :=
  policy.preferredBaseOnly &&
    pe32ByteTreeValid pe.bytes &&
    parsePE32Tree pe.bytes == some pe &&
    pe.bytes.length <= pe32AddressSpaceSize &&
    pe32PowerOfTwo pe.fileAlignment &&
    pe32PowerOfTwo pe.sectionAlignment &&
    pe.fileAlignment <= pe.sectionAlignment &&
    (4096 <= pe.sectionAlignment || pe.fileAlignment == pe.sectionAlignment) &&
    pe.imageBase % 0x10000 == 0 &&
    pe.sizeOfImage > 0 &&
    pe32SpanBounded pe.imageBase pe.sizeOfImage &&
    match readPE32CheckedHeader pe with
    | none => false
    | some header =>
        pe32HeaderAndImageSizesValid pe header &&
          pe32EntrypointValid pe &&
          pe32DirectorySlotValid pe header 1
            pe.importDirectoryRva pe.importDirectorySize &&
          pe32DirectorySlotValid pe header 5
            pe.relocationDirectoryRva pe.relocationDirectorySize &&
          pe32DirectorySlotValid pe header 9
            pe.tlsDirectoryRva pe.tlsDirectorySize

def preferredBaseLoaderImageValid (pe : PE32) : Bool :=
  pe32LoaderImageValid preferredBaseOnlyLoaderPolicy pe

/-- Stable projections from the nested loader checker.  Downstream proofs use
this object instead of repeatedly depending on the checker's conjunction
layout. -/
structure PreferredBaseLoaderImageFacts (pe : PE32) where
  bytesValid : pe32ByteTreeValid pe.bytes = true
  imageSpanValid : pe32SpanBounded pe.imageBase pe.sizeOfImage = true
  header : PE32CheckedHeader
  headerRead : readPE32CheckedHeader pe = some header
  headersBounded : pe.sizeOfHeaders <= pe.bytes.length
  sectionListValid :
    pe32SectionListValid pe pe.sizeOfHeaders pe.sizeOfHeaders pe.sections = true

def preferredBaseLoaderImageValid_facts (pe : PE32)
    (valid : preferredBaseLoaderImageValid pe = true) :
    PreferredBaseLoaderImageFacts pe := by
  unfold preferredBaseLoaderImageValid pe32LoaderImageValid at valid
  simp only [preferredBaseOnlyLoaderPolicy, Bool.true_and, Bool.and_eq_true]
    at valid
  have bytesValid := valid.1.1.1.1.1.1.1.1.1.1
  have imageSpanValid := valid.1.2
  have headerValid := valid.2
  cases headerResult : readPE32CheckedHeader pe with
  | none => simp [headerResult] at headerValid
  | some header =>
      simp only [headerResult, Bool.and_eq_true] at headerValid
      have sizesValid := headerValid.1.1.1.1
      unfold pe32HeaderAndImageSizesValid at sizesValid
      split at sizesValid
      · contradiction
      · simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at sizesValid
        exact {
          bytesValid
          imageSpanValid
          header
          headerRead := headerResult
          headersBounded := sizesValid.1.1.2
          sectionListValid := sizesValid.2
        }

theorem preferredBaseLoaderImageValid_bytes (pe : PE32)
    (valid : preferredBaseLoaderImageValid pe = true) :
    pe32ByteTreeValid pe.bytes = true :=
  (preferredBaseLoaderImageValid_facts pe valid).bytesValid

theorem preferredBaseLoaderImageValid_image_span (pe : PE32)
    (valid : preferredBaseLoaderImageValid pe = true) :
    pe32SpanBounded pe.imageBase pe.sizeOfImage = true :=
  (preferredBaseLoaderImageValid_facts pe valid).imageSpanValid

theorem preferredBaseLoaderImageValid_headers_bounded (pe : PE32)
    (valid : preferredBaseLoaderImageValid pe = true) :
    pe.sizeOfHeaders <= pe.bytes.length :=
  (preferredBaseLoaderImageValid_facts pe valid).headersBounded

theorem preferredBaseLoaderImageValid_section_raw_bounded (pe : PE32)
    (valid : preferredBaseLoaderImageValid pe = true) (sec : Section)
    (member : sec ∈ pe.sections) :
    sec.rawPointer + sec.rawSize <= pe.bytes.length :=
  pe32SectionListValid_raw_bounded pe pe.sizeOfHeaders pe.sizeOfHeaders
    pe.sections
    (preferredBaseLoaderImageValid_facts pe valid).sectionListValid sec member

theorem preferredBaseLoaderImageValid_rvaByte_isSome (pe : PE32)
    (valid : preferredBaseLoaderImageValid pe = true) (rva : Nat)
    (region : rva < pe.sizeOfHeaders ∨
      ∃ sec, sec ∈ pe.sections ∧ sec.virtualAddress <= rva ∧
        rva < sec.virtualAddress + sec.mappedSize) :
    (rvaByte pe rva).isSome = true := by
  unfold rvaByte
  split
  · exact pe32ByteTreeValid_readByte_isSome pe.bytes
      (preferredBaseLoaderImageValid_bytes pe valid)
      (by
        have headersBounded :=
          preferredBaseLoaderImageValid_headers_bounded pe valid
        omega)
  · rcases region with header | ⟨sec, member, lower, upper⟩
    · contradiction
    · have foundSome :
          (pe.sections.find? (fun candidate =>
            candidate.virtualAddress <= rva &&
              rva < candidate.virtualAddress + candidate.mappedSize)).isSome =
            true := by
        simp only [List.find?_isSome]
        exact ⟨sec, member, by
          simp only [Bool.and_eq_true, decide_eq_true_eq]
          exact ⟨lower, upper⟩⟩
      cases sectionResult : pe.sections.find? (fun candidate =>
          candidate.virtualAddress <= rva &&
            rva < candidate.virtualAddress + candidate.mappedSize) with
      | none => simp [sectionResult] at foundSome
      | some selected =>
          change (if rva - selected.virtualAddress < selected.rawSize then
            pe.bytes.readByte (selected.rawPointer +
              (rva - selected.virtualAddress)) else some 0).isSome = true
          split
          · apply pe32ByteTreeValid_readByte_isSome pe.bytes
              (preferredBaseLoaderImageValid_bytes pe valid)
            have selectedMember := List.mem_of_find?_eq_some sectionResult
            have rawBounded := preferredBaseLoaderImageValid_section_raw_bounded
              pe valid selected selectedMember
            omega
          · simp

end StageA.Relational
