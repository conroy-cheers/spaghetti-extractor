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

end StageA.Relational
