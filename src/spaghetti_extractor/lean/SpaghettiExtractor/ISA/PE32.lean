import SpaghettiExtractor.ISA.Bytes

namespace SpaghettiExtractor.ISA.Formal

structure Section where
  virtualSize : Nat
  virtualAddress : Nat
  rawSize : Nat
  rawPointer : Nat
  characteristics : Nat
deriving Repr, DecidableEq

def Section.mappedSize (sec : Section) : Nat :=
  if sec.virtualSize = 0 then sec.rawSize else sec.virtualSize

def Section.executable (sec : Section) : Bool :=
  Nat.testBit sec.characteristics 29

def Section.writable (sec : Section) : Bool :=
  Nat.testBit sec.characteristics 31

structure PEDataDirectory where
  rva : Nat
  size : Nat
deriving Repr, DecidableEq

structure PE32 where
  bytes : ByteTree
  peOffset : Nat
  entrypointRva : Nat
  imageBase : Nat
  sectionAlignment : Nat
  fileAlignment : Nat
  sizeOfImage : Nat
  sizeOfHeaders : Nat
  importDirectoryRva : Nat
  importDirectorySize : Nat
  tlsDirectoryRva : Nat
  tlsDirectorySize : Nat
  relocationDirectoryRva : Nat
  relocationDirectorySize : Nat
  sections : List Section
deriving Repr, DecidableEq

structure PEMetadata where
  peOffset : Nat
  entrypointRva : Nat
  imageBase : Nat
  sectionAlignment : Nat
  fileAlignment : Nat
  sizeOfImage : Nat
  sizeOfHeaders : Nat
  importDirectoryRva : Nat
  importDirectorySize : Nat
  tlsDirectoryRva : Nat
  tlsDirectorySize : Nat
  relocationDirectoryRva : Nat
  relocationDirectorySize : Nat
  sections : List Section
deriving Repr, DecidableEq

def PE32.metadata (pe : PE32) : PEMetadata := {
  peOffset := pe.peOffset
  entrypointRva := pe.entrypointRva
  imageBase := pe.imageBase
  sectionAlignment := pe.sectionAlignment
  fileAlignment := pe.fileAlignment
  sizeOfImage := pe.sizeOfImage
  sizeOfHeaders := pe.sizeOfHeaders
  importDirectoryRva := pe.importDirectoryRva
  importDirectorySize := pe.importDirectorySize
  tlsDirectoryRva := pe.tlsDirectoryRva
  tlsDirectorySize := pe.tlsDirectorySize
  relocationDirectoryRva := pe.relocationDirectoryRva
  relocationDirectorySize := pe.relocationDirectorySize
  sections := pe.sections
}

def PEMetadata.toPE32 (metadata : PEMetadata) (bytes : ByteTree) : PE32 := {
  bytes
  peOffset := metadata.peOffset
  entrypointRva := metadata.entrypointRva
  imageBase := metadata.imageBase
  sectionAlignment := metadata.sectionAlignment
  fileAlignment := metadata.fileAlignment
  sizeOfImage := metadata.sizeOfImage
  sizeOfHeaders := metadata.sizeOfHeaders
  importDirectoryRva := metadata.importDirectoryRva
  importDirectorySize := metadata.importDirectorySize
  tlsDirectoryRva := metadata.tlsDirectoryRva
  tlsDirectorySize := metadata.tlsDirectorySize
  relocationDirectoryRva := metadata.relocationDirectoryRva
  relocationDirectorySize := metadata.relocationDirectorySize
  sections := metadata.sections
}

inductive ImportName where
  | symbol (bytes : Bytes)
  | ordinal (value : Nat)
deriving Repr, DecidableEq

structure PEImport where
  dll : Bytes
  name : ImportName
  iatRva : Nat
deriving Repr, DecidableEq

structure BaseRelocation where
  rva : Nat
  kind : Nat
deriving Repr, DecidableEq

def parseSection (bytes : Bytes) (offset : Nat) : Option Section := do
  let virtualSize <- readU32 bytes (offset + 8)
  let virtualAddress <- readU32 bytes (offset + 12)
  let rawSize <- readU32 bytes (offset + 16)
  let rawPointer <- readU32 bytes (offset + 20)
  let characteristics <- readU32 bytes (offset + 36)
  pure { virtualSize, virtualAddress, rawSize, rawPointer, characteristics }

def parseSections (bytes : Bytes) (offset count : Nat) : Option (List Section) :=
  match count with
  | 0 => some []
  | count + 1 => do
      let sec <- parseSection bytes offset
      let tail <- parseSections bytes (offset + 40) count
      pure (sec :: tail)

def parsePEMetadata (bytes : Bytes) : Option PEMetadata := do
  let mz0 <- readByte bytes 0
  let mz1 <- readByte bytes 1
  if mz0 != 0x4d || mz1 != 0x5a then none else
  let peOffset <- readU32 bytes 0x3c
  let p0 <- readByte bytes peOffset
  let p1 <- readByte bytes (peOffset + 1)
  let p2 <- readByte bytes (peOffset + 2)
  let p3 <- readByte bytes (peOffset + 3)
  if p0 != 0x50 || p1 != 0x45 || p2 != 0 || p3 != 0 then none else
  let machine <- readU16 bytes (peOffset + 4)
  let sectionCount <- readU16 bytes (peOffset + 6)
  let optionalSize <- readU16 bytes (peOffset + 20)
  let _characteristics <- readU16 bytes (peOffset + 22)
  let optionalOffset := peOffset + 24
  let magic <- readU16 bytes optionalOffset
  if machine != 0x14c || magic != 0x10b || optionalSize < 224 then none else
  let entrypointRva <- readU32 bytes (optionalOffset + 16)
  let imageBase <- readU32 bytes (optionalOffset + 28)
  let sectionAlignment <- readU32 bytes (optionalOffset + 32)
  let fileAlignment <- readU32 bytes (optionalOffset + 36)
  let sizeOfImage <- readU32 bytes (optionalOffset + 56)
  let sizeOfHeaders <- readU32 bytes (optionalOffset + 60)
  let numberOfRvaAndSizes <- readU32 bytes (optionalOffset + 92)
  if numberOfRvaAndSizes > (optionalSize - 96) / 8 then none else
  let importDirectoryRva <- readU32 bytes (optionalOffset + 104)
  let importDirectorySize <- readU32 bytes (optionalOffset + 108)
  let tlsDirectoryRva <- readU32 bytes (optionalOffset + 168)
  let tlsDirectorySize <- readU32 bytes (optionalOffset + 172)
  let relocationDirectoryRva <- readU32 bytes (optionalOffset + 136)
  let relocationDirectorySize <- readU32 bytes (optionalOffset + 140)
  let sections <- parseSections bytes (optionalOffset + optionalSize) sectionCount
  pure {
    peOffset,
    entrypointRva,
    imageBase,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    sizeOfHeaders,
    importDirectoryRva,
    importDirectorySize,
    tlsDirectoryRva,
    tlsDirectorySize,
    relocationDirectoryRva,
    relocationDirectorySize,
    sections,
  }

def readTreeU16 (bytes : ByteTree) (offset : Nat) : Option Nat := do
  let b0 <- bytes.readByte offset
  let b1 <- bytes.readByte (offset + 1)
  if b0 < 256 && b1 < 256 then pure (b0 + b1 * 256) else none

def readTreeU32 (bytes : ByteTree) (offset : Nat) : Option Nat := do
  let lo <- readTreeU16 bytes offset
  let hi <- readTreeU16 bytes (offset + 2)
  pure (lo + hi * 65536)

def parseTreeSection (bytes : ByteTree) (offset : Nat) : Option Section := do
  let virtualSize <- readTreeU32 bytes (offset + 8)
  let virtualAddress <- readTreeU32 bytes (offset + 12)
  let rawSize <- readTreeU32 bytes (offset + 16)
  let rawPointer <- readTreeU32 bytes (offset + 20)
  let characteristics <- readTreeU32 bytes (offset + 36)
  pure { virtualSize, virtualAddress, rawSize, rawPointer, characteristics }

def parseTreeSections (bytes : ByteTree) (offset count : Nat) : Option (List Section) :=
  match count with
  | 0 => some []
  | count + 1 => do
      let sec <- parseTreeSection bytes offset
      let tail <- parseTreeSections bytes (offset + 40) count
      pure (sec :: tail)

def parsePEMetadataTree (bytes : ByteTree) : Option PEMetadata := do
  let mz0 <- bytes.readByte 0
  let mz1 <- bytes.readByte 1
  if mz0 != 0x4d || mz1 != 0x5a then none else
  let peOffset <- readTreeU32 bytes 0x3c
  let p0 <- bytes.readByte peOffset
  let p1 <- bytes.readByte (peOffset + 1)
  let p2 <- bytes.readByte (peOffset + 2)
  let p3 <- bytes.readByte (peOffset + 3)
  if p0 != 0x50 || p1 != 0x45 || p2 != 0 || p3 != 0 then none else
  let machine <- readTreeU16 bytes (peOffset + 4)
  let sectionCount <- readTreeU16 bytes (peOffset + 6)
  let optionalSize <- readTreeU16 bytes (peOffset + 20)
  let _characteristics <- readTreeU16 bytes (peOffset + 22)
  let optionalOffset := peOffset + 24
  let magic <- readTreeU16 bytes optionalOffset
  if machine != 0x14c || magic != 0x10b || optionalSize < 224 then none else
  let entrypointRva <- readTreeU32 bytes (optionalOffset + 16)
  let imageBase <- readTreeU32 bytes (optionalOffset + 28)
  let sectionAlignment <- readTreeU32 bytes (optionalOffset + 32)
  let fileAlignment <- readTreeU32 bytes (optionalOffset + 36)
  let sizeOfImage <- readTreeU32 bytes (optionalOffset + 56)
  let sizeOfHeaders <- readTreeU32 bytes (optionalOffset + 60)
  let numberOfRvaAndSizes <- readTreeU32 bytes (optionalOffset + 92)
  if numberOfRvaAndSizes > (optionalSize - 96) / 8 then none else
  let importDirectoryRva <- readTreeU32 bytes (optionalOffset + 104)
  let importDirectorySize <- readTreeU32 bytes (optionalOffset + 108)
  let tlsDirectoryRva <- readTreeU32 bytes (optionalOffset + 168)
  let tlsDirectorySize <- readTreeU32 bytes (optionalOffset + 172)
  let relocationDirectoryRva <- readTreeU32 bytes (optionalOffset + 136)
  let relocationDirectorySize <- readTreeU32 bytes (optionalOffset + 140)
  let sections <- parseTreeSections bytes (optionalOffset + optionalSize) sectionCount
  pure {
    peOffset,
    entrypointRva,
    imageBase,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    sizeOfHeaders,
    importDirectoryRva,
    importDirectorySize,
    tlsDirectoryRva,
    tlsDirectorySize,
    relocationDirectoryRva,
    relocationDirectorySize,
    sections,
  }

def parsePE32 (bytes : Bytes) : Option PE32 :=
  (parsePEMetadata bytes).map (fun metadata => metadata.toPE32 (ByteTree.ofBytes bytes))

def parsePE32Tree (bytes : ByteTree) : Option PE32 :=
  (parsePEMetadataTree bytes).map (fun metadata => metadata.toPE32 bytes)

def sectionBytes (pe : PE32) (sec : Section) : Option Bytes :=
  if sec.rawPointer + sec.rawSize > pe.bytes.length then
    none
  else if sec.mappedSize > sec.rawSize then do
    let raw <- pe.bytes.readBytes sec.rawPointer sec.rawSize
    pure (raw ++ List.replicate (sec.mappedSize - sec.rawSize) 0)
  else
    pe.bytes.readBytes sec.rawPointer sec.mappedSize

def rvaByte (pe : PE32) (rva : Nat) : Option Byte := do
  if rva < pe.sizeOfHeaders then
    pe.bytes.readByte rva
  else
    let sec <- pe.sections.find? (fun sec =>
      sec.virtualAddress <= rva && rva < sec.virtualAddress + sec.mappedSize)
    let offset := rva - sec.virtualAddress
    if offset < sec.rawSize then
      pe.bytes.readByte (sec.rawPointer + offset)
    else
      pure 0

theorem rvaByte_region (pe : PE32) (rva expected : Nat)
    (checked : rvaByte pe rva = some expected) :
    rva < pe.sizeOfHeaders ∨
      ∃ sec, sec ∈ pe.sections ∧ sec.virtualAddress <= rva ∧
        rva < sec.virtualAddress + sec.mappedSize := by
  unfold rvaByte at checked
  split at checked
  · exact Or.inl (by assumption)
  · right
    cases found : pe.sections.find? (fun sec =>
        sec.virtualAddress <= rva &&
          rva < sec.virtualAddress + sec.mappedSize) with
    | none => simp [found] at checked
    | some sec =>
        have member := List.mem_of_find?_eq_some found
        have predicate := List.find?_some
          (p := fun candidate : Section =>
            candidate.virtualAddress <= rva &&
              rva < candidate.virtualAddress + candidate.mappedSize)
          (a := sec) found
        simp only [Bool.and_eq_true, decide_eq_true_eq] at predicate
        exact ⟨sec, member, predicate⟩

def readRvaU16 (pe : PE32) (rva : Nat) : Option Nat := do
  let b0 <- rvaByte pe rva
  let b1 <- rvaByte pe (rva + 1)
  if b0 < 256 && b1 < 256 then pure (b0 + b1 * 256) else none

def readRvaU32 (pe : PE32) (rva : Nat) : Option Nat := do
  let lo <- readRvaU16 pe rva
  let hi <- readRvaU16 pe (rva + 2)
  pure (lo + hi * 65536)

/-- The exact COFF `Characteristics` word backing this parsed PE32 image. -/
def PE32.characteristics (pe : PE32) : Nat :=
  (readTreeU16 pe.bytes (pe.peOffset + 22)).getD 0

def PE32.isDll (pe : PE32) : Bool :=
  Nat.testBit pe.characteristics 13

/-- Read a PE32 data-directory slot from the exact optional-header bytes.  The
outer `Option` rejects malformed directory metadata; the inner `Option`
distinguishes an absent slot or an all-zero directory from a present one. -/
def PE32.dataDirectory (pe : PE32) (index : Nat) : Option (Option PEDataDirectory) := do
  let optionalSize <- readTreeU16 pe.bytes (pe.peOffset + 20)
  if optionalSize < 96 then none else
  let optionalOffset := pe.peOffset + 24
  let numberOfRvaAndSizes <- readTreeU32 pe.bytes (optionalOffset + 92)
  let directoryCapacity := (optionalSize - 96) / 8
  if numberOfRvaAndSizes > directoryCapacity then none
  else if index >= numberOfRvaAndSizes then pure none
  else
    let directoryOffset := optionalOffset + 96 + index * 8
    let rva <- readTreeU32 pe.bytes directoryOffset
    let size <- readTreeU32 pe.bytes (directoryOffset + 4)
    if rva == 0 && size == 0 then pure none
    else if rva == 0 || size == 0 then none
    else pure (some { rva, size })

/-- Read one byte whose RVA is backed by an exact file byte.  Unlike
`rvaByte`, this does not synthesize zeroes for a section's virtual tail, and it
rejects ambiguous overlapping section mappings. -/
def exactRvaByte (pe : PE32) (rva : Nat) : Option Byte := do
  if rva >= pe.sizeOfImage then none
  else if rva < pe.sizeOfHeaders then
    pe.bytes.readByte rva
  else
    match pe.sections.filter (fun sec =>
        sec.virtualAddress <= rva && rva < sec.virtualAddress + sec.mappedSize) with
    | [sec] =>
        let offset := rva - sec.virtualAddress
        if offset < sec.rawSize then pe.bytes.readByte (sec.rawPointer + offset)
        else none
    | _ => none

def exactRvaSpan (pe : PE32) (rva size : Nat) : Bool :=
  if rva > pe.sizeOfImage || size > pe.sizeOfImage - rva then false
  else if size == 0 then true
  else if rva < pe.sizeOfHeaders then
    size <= pe.sizeOfHeaders - rva && rva <= pe.bytes.length &&
      size <= pe.bytes.length - rva
  else
    match pe.sections.filter (fun sec =>
        sec.virtualAddress <= rva &&
          size <= sec.virtualAddress + sec.mappedSize - rva) with
    | [sec] =>
        let offset := rva - sec.virtualAddress
        offset <= sec.rawSize && size <= sec.rawSize - offset &&
          sec.rawPointer + offset <= pe.bytes.length &&
          size <= pe.bytes.length - (sec.rawPointer + offset)
    | _ => false

def readExactRvaU16 (pe : PE32) (rva : Nat) : Option Nat := do
  let b0 <- exactRvaByte pe rva
  let b1 <- exactRvaByte pe (rva + 1)
  if b0 < 256 && b1 < 256 then pure (b0 + b1 * 256) else none

def readExactRvaU32 (pe : PE32) (rva : Nat) : Option Nat := do
  let lo <- readExactRvaU16 pe rva
  let hi <- readExactRvaU16 pe (rva + 2)
  pure (lo + hi * 65536)

inductive PEExportKind where
  | executableAddress
  | dataAddress
  | forwarder
  | null
deriving Repr, DecidableEq

/-- One Export Address Table slot. `rva` is the exact 32-bit EAT value and
`forwarder` preserves the null-terminated identity bytes without the null. -/
structure PEExport where
  rva : Nat
  kind : PEExportKind
  forwarder : Option Bytes
deriving Repr, DecidableEq

structure PEExportDirectory32 where
  directoryRva : Nat
  directorySize : Nat
  characteristics : Nat
  timeDateStamp : Nat
  majorVersion : Nat
  minorVersion : Nat
  nameRva : Nat
  ordinalBase : Nat
  numberOfFunctions : Nat
  numberOfNames : Nat
  addressOfFunctionsRva : Nat
  addressOfNamesRva : Nat
  addressOfNameOrdinalsRva : Nat
deriving Repr, DecidableEq

def rvaRangeInside (rva size outerRva outerSize : Nat) : Bool :=
  outerRva <= rva && rva <= outerRva + outerSize &&
    size <= outerRva + outerSize - rva

/-- Parse the fixed-width export directory from exact file-backed bytes. -/
def parseExportDirectory32 (pe : PE32) : Option (Option PEExportDirectory32) := do
  let dataDirectory <- pe.dataDirectory 0
  match dataDirectory with
  | none => pure none
  | some directory =>
      if directory.rva > pe.sizeOfImage ||
          directory.size > pe.sizeOfImage - directory.rva ||
          directory.size < 40 || !exactRvaSpan pe directory.rva directory.size then
        none
      else
        let characteristics <- readExactRvaU32 pe directory.rva
        let timeDateStamp <- readExactRvaU32 pe (directory.rva + 4)
        let majorVersion <- readExactRvaU16 pe (directory.rva + 8)
        let minorVersion <- readExactRvaU16 pe (directory.rva + 10)
        let nameRva <- readExactRvaU32 pe (directory.rva + 12)
        let ordinalBase <- readExactRvaU32 pe (directory.rva + 16)
        let numberOfFunctions <- readExactRvaU32 pe (directory.rva + 20)
        let numberOfNames <- readExactRvaU32 pe (directory.rva + 24)
        let addressOfFunctionsRva <- readExactRvaU32 pe (directory.rva + 28)
        let addressOfNamesRva <- readExactRvaU32 pe (directory.rva + 32)
        let addressOfNameOrdinalsRva <- readExactRvaU32 pe (directory.rva + 36)
        if numberOfNames > numberOfFunctions then none else
        pure (some {
          directoryRva := directory.rva,
          directorySize := directory.size,
          characteristics,
          timeDateStamp,
          majorVersion,
          minorVersion,
          nameRva,
          ordinalBase,
          numberOfFunctions,
          numberOfNames,
          addressOfFunctionsRva,
          addressOfNamesRva,
          addressOfNameOrdinalsRva,
        })

def readExactForwarderIdentityAux (pe : PE32) : Nat -> Nat -> Option Bytes
  | _, 0 => none
  | rva, fuel + 1 => do
      let byte <- exactRvaByte pe rva
      if byte == 0 then pure []
      else if byte >= 128 then none
      else
        let tail <- readExactForwarderIdentityAux pe (rva + 1) fuel
        pure (byte :: tail)

def readExactForwarderIdentity
    (pe : PE32) (directory : PEExportDirectory32) (rva : Nat) : Option Bytes := do
  if !rvaRangeInside rva 1 directory.directoryRva directory.directorySize then none else
  let directoryEnd := directory.directoryRva + directory.directorySize
  let identity <- readExactForwarderIdentityAux pe rva (directoryEnd - rva)
  if identity.isEmpty then none else pure identity

def PE32.executableRva (pe : PE32) (rva : Nat) : Bool :=
  match pe.sections.filter (fun sec =>
      sec.virtualAddress <= rva && rva < sec.virtualAddress + sec.mappedSize) with
  | [sec] => sec.executable && (exactRvaByte pe rva).isSome
  | _ => false

def classifyExport
    (pe : PE32) (directory : PEExportDirectory32) (rva : Nat) : Option PEExport := do
  if rva == 0 then
    pure { rva, kind := .null, forwarder := none }
  else if rvaRangeInside rva 1 directory.directoryRva directory.directorySize then
    let identity <- readExactForwarderIdentity pe directory rva
    pure { rva, kind := .forwarder, forwarder := some identity }
  else if pe.executableRva rva then
    pure { rva, kind := .executableAddress, forwarder := none }
  else if (exactRvaByte pe rva).isSome then
    pure { rva, kind := .dataAddress, forwarder := none }
  else
    none

def parseExportsAux (pe : PE32) (directory : PEExportDirectory32) :
    Nat -> Nat -> Option (List PEExport)
  | _, 0 => pure []
  | eatRva, count + 1 => do
      let targetRva <- readExactRvaU32 pe eatRva
      let exported <- classifyExport pe directory targetRva
      let tail <- parseExportsAux pe directory (eatRva + 4) count
      pure (exported :: tail)

/-- Parse every Export Address Table slot from exact bytes.  Absent and
zero-function directories produce `some []`; any malformed slot rejects the
entire export inventory. -/
def parseExports (pe : PE32) : Option (List PEExport) := do
  let directory <- parseExportDirectory32 pe
  match directory with
  | none => pure []
  | some exportDirectory =>
      if exportDirectory.numberOfFunctions == 0 then pure []
      else
        let eatSize := exportDirectory.numberOfFunctions * 4
        if exportDirectory.numberOfFunctions > exportDirectory.directorySize / 4 ||
            !rvaRangeInside exportDirectory.addressOfFunctionsRva eatSize
              exportDirectory.directoryRva exportDirectory.directorySize then
          none
        else
          parseExportsAux pe exportDirectory exportDirectory.addressOfFunctionsRva
            exportDirectory.numberOfFunctions

structure PETlsDirectory32 where
  rawDataStartVa : Nat
  rawDataEndVa : Nat
  indexVa : Nat
  callbacksVa : Nat
  zeroFillSize : Nat
  characteristics : Nat
deriving Repr, DecidableEq

/-- Parse the fixed-width PE32 TLS directory from mapped image bytes.  The
outer `Option` reports a malformed directory; the inner `Option` distinguishes
an absent directory from a present one. -/
def parseTlsDirectory32 (pe : PE32) : Option (Option PETlsDirectory32) := do
  if pe.tlsDirectoryRva == 0 && pe.tlsDirectorySize == 0 then
    pure none
  else if pe.tlsDirectoryRva == 0 || pe.tlsDirectorySize < 24 then
    none
  else
    let rawDataStartVa <- readRvaU32 pe pe.tlsDirectoryRva
    let rawDataEndVa <- readRvaU32 pe (pe.tlsDirectoryRva + 4)
    let indexVa <- readRvaU32 pe (pe.tlsDirectoryRva + 8)
    let callbacksVa <- readRvaU32 pe (pe.tlsDirectoryRva + 12)
    let zeroFillSize <- readRvaU32 pe (pe.tlsDirectoryRva + 16)
    let characteristics <- readRvaU32 pe (pe.tlsDirectoryRva + 20)
    pure (some {
      rawDataStartVa,
      rawDataEndVa,
      indexVa,
      callbacksVa,
      zeroFillSize,
      characteristics,
    })

def absoluteImageVaToRva (pe : PE32) (absolute : Nat) : Option Nat :=
  if pe.imageBase <= absolute && absolute < pe.imageBase + pe.sizeOfImage then
    some (absolute - pe.imageBase)
  else
    none

/-- Read a null-terminated PE32 TLS callback array.  Fuel is the exact number
of complete 32-bit slots left in the mapped image, so a missing terminator
fails closed rather than accepting a truncated inventory. -/
def parseTlsCallbackRvasAux (pe : PE32) : Nat -> Nat -> Option (List Nat)
  | _, 0 => none
  | arrayRva, fuel + 1 => do
      let callbackVa <- readRvaU32 pe arrayRva
      if callbackVa == 0 then
        pure []
      else
        let callbackRva <- absoluteImageVaToRva pe callbackVa
        let tail <- parseTlsCallbackRvasAux pe (arrayRva + 4) fuel
        pure (callbackRva :: tail)

def parseTlsCallbackRvas (pe : PE32) : Option (List Nat) := do
  let directory <- parseTlsDirectory32 pe
  match directory with
  | none => pure []
  | some tls =>
      if tls.callbacksVa == 0 then
        pure []
      else
        let callbacksRva <- absoluteImageVaToRva pe tls.callbacksVa
        let callbackSlots := (pe.sizeOfImage - callbacksRva) / 4
        parseTlsCallbackRvasAux pe callbacksRva callbackSlots

def littleEndianValue : Bytes -> Nat -> Nat
  | [], _ => 0
  | byte :: tail, shift => byte * 2 ^ shift + littleEndianValue tail (shift + 8)

def readRvaLittleEndian (pe : PE32) (rva size : Nat) : Option Nat := do
  let bytes <- (List.range size).mapM fun offset => rvaByte pe (rva + offset)
  pure (littleEndianValue bytes 0)

def readCStringRva : PE32 -> Nat -> Nat -> Option Bytes
  | _, _, 0 => none
  | pe, rva, fuel + 1 => do
      let byte <- rvaByte pe rva
      if byte == 0 then
        pure []
      else if byte < 256 then
        let tail <- readCStringRva pe (rva + 1) fuel
        pure (byte :: tail)
      else
        none

def parseImportThunks : PE32 -> Bytes -> Nat -> Nat -> Nat -> Option (List PEImport)
  | _, _, _, _, 0 => none
  | pe, dll, lookupRva, iatRva, fuel + 1 => do
      let value <- readRvaU32 pe lookupRva
      if value == 0 then
        pure []
      else
        let name <-
          if Nat.testBit value 31 then
            pure (.ordinal (value % 65536))
          else do
            let _ <- readRvaU16 pe value
            let bytes <- readCStringRva pe (value + 2) 4096
            pure (.symbol bytes)
        let tail <- parseImportThunks pe dll (lookupRva + 4) (iatRva + 4) fuel
        pure ({ dll, name, iatRva } :: tail)

def parseImportDescriptors : PE32 -> Nat -> Nat -> Option (List PEImport)
  | _, _, 0 => none
  | pe, offset, fuel + 1 => do
      if offset + 20 > pe.importDirectorySize then none else
      let descriptorRva := pe.importDirectoryRva + offset
      let originalFirstThunk <- readRvaU32 pe descriptorRva
      let timestamp <- readRvaU32 pe (descriptorRva + 4)
      let forwarderChain <- readRvaU32 pe (descriptorRva + 8)
      let nameRva <- readRvaU32 pe (descriptorRva + 12)
      let firstThunk <- readRvaU32 pe (descriptorRva + 16)
      if originalFirstThunk == 0 && timestamp == 0 && forwarderChain == 0 && nameRva == 0 && firstThunk == 0 then
        pure []
      else if nameRva == 0 || firstThunk == 0 then
        none
      else
        let dll <- readCStringRva pe nameRva 4096
        let lookupRva := if originalFirstThunk == 0 then firstThunk else originalFirstThunk
        let imports <- parseImportThunks pe dll lookupRva firstThunk 65536
        let tail <- parseImportDescriptors pe (offset + 20) fuel
        pure (imports ++ tail)

def parseImports (pe : PE32) : Option (List PEImport) :=
  if pe.importDirectoryRva == 0 && pe.importDirectorySize == 0 then
    some []
  else if pe.importDirectoryRva == 0 || pe.importDirectorySize < 20 then
    none
  else
    parseImportDescriptors pe 0 (pe.importDirectorySize / 20 + 1)

def imageRangeExcludesIat (imports : List PEImport) (rva size : Nat) : Bool :=
  !imports.any fun imported =>
    rva < imported.iatRva + 4 && imported.iatRva < rva + size

def readImmutableImageWordWithImports (pe : PE32) (imports : List PEImport)
    (absolute size : Nat) : Option Nat := do
  if absolute < pe.imageBase || size = 0 || absolute + size > 2^32 then none else
  let rva := absolute - pe.imageBase
  if rva + size > pe.sizeOfImage then none else
  if !imageRangeExcludesIat imports rva size then none else
  if !(rva + size <= pe.sizeOfHeaders) then
    let _ <- pe.sections.find? fun sec =>
      !sec.writable && sec.virtualAddress <= rva &&
        rva + size <= sec.virtualAddress + sec.mappedSize
  readRvaLittleEndian pe rva size

theorem readImmutableImageWordWithImports_excludesIat
    (pe : PE32) (imports : List PEImport) (absolute size expected : Nat)
    (checked : readImmutableImageWordWithImports pe imports absolute size =
      some expected) :
    imageRangeExcludesIat imports (absolute - pe.imageBase) size = true := by
  unfold readImmutableImageWordWithImports at checked
  split at checked
  · simp at checked
  · dsimp only at checked
    split at checked
    · simp at checked
    · split at checked
      · simp at checked
      · simp_all

def readImmutableImageWord (pe : PE32) (absolute size : Nat) : Option Nat := do
  let imports <- parseImports pe
  readImmutableImageWordWithImports pe imports absolute size

/-- Check the exact TLS callback values and null terminator through the
immutable-image reader.  `ImmutableImageWordMemory` then keeps this launch
inventory stable while earlier TLS callbacks execute. -/
def tlsCallbackArrayValuesImmutable (pe : PE32) : Nat -> List Nat -> Bool
  | address, [] => readImmutableImageWord pe address 4 == some 0
  | address, callbackRva :: callbackRvas =>
      readImmutableImageWord pe address 4 == some (pe.imageBase + callbackRva) &&
        tlsCallbackArrayValuesImmutable pe (address + 4) callbackRvas

def tlsCallbackArrayImmutable (pe : PE32) : Bool :=
  match parseTlsDirectory32 pe, parseTlsCallbackRvas pe with
  | some none, some [] => true
  | some (some tls), some callbackRvas =>
      if tls.callbacksVa == 0 then callbackRvas.isEmpty
      else
        readImmutableImageWord pe
            (pe.imageBase + pe.tlsDirectoryRva + 12) 4 == some tls.callbacksVa &&
          tlsCallbackArrayValuesImmutable pe tls.callbacksVa callbackRvas
  | _, _ => false

theorem readImmutableImageWord_bounds (pe : PE32) (absolute size expected : Nat)
    (checked : readImmutableImageWord pe absolute size = some expected) :
    pe.imageBase <= absolute ∧ absolute + size <= 2^32 ∧
      absolute + size <= pe.imageBase + pe.sizeOfImage := by
  unfold readImmutableImageWord at checked
  cases importsResult : parseImports pe with
  | none => simp [importsResult] at checked
  | some imports =>
      simp only [importsResult, Option.bind_some] at checked
      unfold readImmutableImageWordWithImports at checked
      split at checked
      · simp at checked
      · simp_all
        omega

theorem readImmutableImageWord_region (pe : PE32) (absolute size expected : Nat)
    (checked : readImmutableImageWord pe absolute size = some expected) :
    absolute + size <= pe.imageBase + pe.sizeOfHeaders ∨
      ∃ sec, sec ∈ pe.sections ∧ sec.writable = false ∧
        pe.imageBase + sec.virtualAddress <= absolute ∧
        absolute + size <= pe.imageBase + sec.virtualAddress + sec.mappedSize := by
  have bounds := readImmutableImageWord_bounds pe absolute size expected checked
  unfold readImmutableImageWord at checked
  cases importsResult : parseImports pe with
  | none => simp [importsResult] at checked
  | some imports =>
    simp only [importsResult, Option.bind_some] at checked
    unfold readImmutableImageWordWithImports at checked
    split at checked
    · simp at checked
    · dsimp only at checked
      split at checked
      · simp at checked
      · split at checked
        · right
          cases found : pe.sections.find? (fun sec =>
                !sec.writable && sec.virtualAddress <= absolute - pe.imageBase &&
                  absolute - pe.imageBase + size <=
                    sec.virtualAddress + sec.mappedSize) with
          | none => simp [found] at checked
          | some sec =>
              have member := List.mem_of_find?_eq_some found
              have predicate := List.find?_some
                (p := fun candidate : Section =>
                  !candidate.writable &&
                    candidate.virtualAddress <= absolute - pe.imageBase &&
                    absolute - pe.imageBase + size <=
                      candidate.virtualAddress + candidate.mappedSize)
                (a := sec) found
              simp only [Bool.and_eq_true, decide_eq_true_eq] at predicate
              have immutable := predicate.1.1
              rw [Bool.not_eq_true'] at immutable
              refine ⟨sec, member, immutable, ?_, ?_⟩ <;> omega
        · left
          simp_all
          omega

structure ImportThunkCertificate where
  lookupRva : Nat
  iatRva : Nat
  nameRva : Nat
  imported : PEImport
deriving Repr, DecidableEq

structure ImportDescriptorCertificate where
  descriptorRva : Nat
  lookupRva : Nat
  firstThunk : Nat
  nameRva : Nat
  dll : Bytes
  thunks : List ImportThunkCertificate
deriving Repr, DecidableEq

structure ImportTableCertificate where
  descriptors : List ImportDescriptorCertificate
deriving Repr, DecidableEq

def ImportTableCertificate.imports (certificate : ImportTableCertificate) : List PEImport :=
  certificate.descriptors.flatMap fun descriptor => descriptor.thunks.map (·.imported)

def cStringAtRva (pe : PE32) : Nat -> Bytes -> Bool
  | rva, [] => rvaByte pe rva == some 0
  | rva, head :: tail => rvaByte pe rva == some head && cStringAtRva pe (rva + 1) tail

def importThunkValid (pe : PE32) (descriptor : ImportDescriptorCertificate)
    (index : Nat) (thunk : ImportThunkCertificate) : Bool :=
  thunk.lookupRva == descriptor.lookupRva + index * 4 &&
  thunk.iatRva == descriptor.firstThunk + index * 4 &&
  thunk.imported.dll == descriptor.dll &&
  thunk.imported.iatRva == thunk.iatRva &&
  match readRvaU32 pe thunk.lookupRva, thunk.imported.name with
  | some value, .ordinal ordinal =>
      Nat.testBit value 31 && value % 65536 == ordinal && thunk.nameRva == 0
  | some value, .symbol name =>
      !Nat.testBit value 31 && value == thunk.nameRva &&
        (readRvaU16 pe thunk.nameRva).isSome && cStringAtRva pe (thunk.nameRva + 2) name
  | _, _ => false

def importThunksValid (pe : PE32) (descriptor : ImportDescriptorCertificate) :
    Nat -> List ImportThunkCertificate -> Bool
  | index, [] => readRvaU32 pe (descriptor.lookupRva + index * 4) == some 0
  | index, thunk :: tail =>
      importThunkValid pe descriptor index thunk && importThunksValid pe descriptor (index + 1) tail

def importDescriptorValid (pe : PE32) (index : Nat)
    (descriptor : ImportDescriptorCertificate) : Bool :=
  descriptor.descriptorRva == pe.importDirectoryRva + index * 20 &&
  match readRvaU32 pe descriptor.descriptorRva,
      readRvaU32 pe (descriptor.descriptorRva + 12),
      readRvaU32 pe (descriptor.descriptorRva + 16) with
  | some originalFirstThunk, some nameRva, some firstThunk =>
      nameRva == descriptor.nameRva && firstThunk == descriptor.firstThunk &&
      descriptor.lookupRva == (if originalFirstThunk == 0 then firstThunk else originalFirstThunk) &&
      nameRva != 0 && firstThunk != 0 && cStringAtRva pe nameRva descriptor.dll &&
      importThunksValid pe descriptor 0 descriptor.thunks
  | _, _, _ => false

def zeroImportDescriptor (pe : PE32) (rva : Nat) : Bool :=
  readRvaU32 pe rva == some 0 && readRvaU32 pe (rva + 4) == some 0 &&
  readRvaU32 pe (rva + 8) == some 0 && readRvaU32 pe (rva + 12) == some 0 &&
  readRvaU32 pe (rva + 16) == some 0

def importDescriptorsValid (pe : PE32) : Nat -> List ImportDescriptorCertificate -> Bool
  | index, [] =>
      index * 20 + 20 <= pe.importDirectorySize &&
        zeroImportDescriptor pe (pe.importDirectoryRva + index * 20)
  | index, descriptor :: tail =>
      (index + 1) * 20 <= pe.importDirectorySize && importDescriptorValid pe index descriptor &&
        importDescriptorsValid pe (index + 1) tail

def importTableValid (pe : PE32) (certificate : ImportTableCertificate) : Bool :=
  if pe.importDirectoryRva == 0 && pe.importDirectorySize == 0 then
    certificate.descriptors.isEmpty
  else
    pe.importDirectoryRva != 0 && pe.importDirectorySize >= 20 &&
      importDescriptorsValid pe 0 certificate.descriptors

def parseRelocationEntries (pe : PE32) (pageRva entriesRva count : Nat) : Option (List BaseRelocation) :=
  match count with
  | 0 => some []
  | count + 1 => do
      let value <- readRvaU16 pe entriesRva
      let kind := value / 4096
      let offset := value % 4096
      let tail <- parseRelocationEntries pe pageRva (entriesRva + 2) count
      if kind == 0 then
        pure tail
      else if kind == 3 then
        pure ({ rva := pageRva + offset, kind } :: tail)
      else
        none

def parseRelocationBlocks : PE32 -> Nat -> Nat -> Option (List BaseRelocation)
  | _, _, 0 => none
  | pe, offset, fuel + 1 => do
      if offset == pe.relocationDirectorySize then pure [] else
      if offset + 8 > pe.relocationDirectorySize then none else
      let blockRva := pe.relocationDirectoryRva + offset
      let pageRva <- readRvaU32 pe blockRva
      let blockSize <- readRvaU32 pe (blockRva + 4)
      if blockSize < 8 || blockSize % 2 != 0 || offset + blockSize > pe.relocationDirectorySize then none else
      let entries <- parseRelocationEntries pe pageRva (blockRva + 8) ((blockSize - 8) / 2)
      let tail <- parseRelocationBlocks pe (offset + blockSize) fuel
      pure (entries ++ tail)

def parseRelocations (pe : PE32) : Option (List BaseRelocation) :=
  if pe.relocationDirectoryRva == 0 && pe.relocationDirectorySize == 0 then
    some []
  else if pe.relocationDirectoryRva == 0 || pe.relocationDirectorySize < 8 then
    none
  else
    parseRelocationBlocks pe 0 (pe.relocationDirectorySize / 8 + 1)


end SpaghettiExtractor.ISA.Formal
