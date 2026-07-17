import Std

namespace StageA.Formal

abbrev Byte := Nat
abbrev Bytes := List Byte
abbrev Word := BitVec 32
abbrev Memory := Word -> BitVec 8
abbrev X87Word := BitVec 80

inductive ByteTree where
  | empty
  | leaf (bytes : Bytes)
  | node (size leftSize : Nat) (left right : ByteTree)
deriving Repr, DecidableEq

def ByteTree.length : ByteTree -> Nat
  | .empty => 0
  | .leaf bytes => bytes.length
  | .node size _ _ _ => size

def ByteTree.mergeRound : List ByteTree -> List ByteTree
  | left :: right :: rest =>
      .node (left.length + right.length) left.length left right :: mergeRound rest
  | rest => rest

def ByteTree.build : Nat -> List ByteTree -> ByteTree
  | _, [] => .empty
  | _, [tree] => tree
  | 0, tree :: _ => tree
  | fuel + 1, trees => build fuel (mergeRound trees)

def ByteTree.chunkBytes (chunkSize : Nat) : Nat -> Bytes -> List Bytes
  | 0, _ => []
  | _, [] => []
  | fuel + 1, bytes =>
      bytes.take chunkSize :: chunkBytes chunkSize fuel (bytes.drop chunkSize)

def ByteTree.ofBytes (bytes : Bytes) : ByteTree :=
  let chunkSize := 1024
  let count := (bytes.length + chunkSize - 1) / chunkSize
  let leaves := (ByteTree.chunkBytes chunkSize count bytes).map ByteTree.leaf
  ByteTree.build count leaves

def ByteTree.readByte : ByteTree -> Nat -> Option Byte
  | .empty, _ => none
  | .leaf bytes, offset => bytes[offset]?
  | .node size leftSize left right, offset =>
      if offset >= size then none
      else if offset < leftSize then left.readByte offset
      else right.readByte (offset - leftSize)

def ByteTree.readBytes (tree : ByteTree) : Nat -> Nat -> Option Bytes
  | _, 0 => some []
  | offset, count + 1 => do
      let head <- tree.readByte offset
      let tail <- tree.readBytes (offset + 1) count
      pure (head :: tail)

inductive X87LoadFormat where
  | float32 | float64 | float80 | int32
deriving Repr, DecidableEq

def X87LoadFormat.byteWidth : X87LoadFormat -> Nat
  | .float32 | .int32 => 4
  | .float64 => 8
  | .float80 => 10

inductive X87StoreFormat where
  | float32 | float64 | float80 | int32
deriving Repr, DecidableEq

inductive X87UnaryOperation where
  | negate
deriving Repr, DecidableEq

inductive X87BinaryOperation where
  | add | multiply | subtract | reverseSubtract | divide | reverseDivide
deriving Repr, DecidableEq

structure X87Semantics where
  load : X87LoadFormat -> X87Word -> BitVec 16 -> X87Word
  store : X87StoreFormat -> X87Word -> BitVec 16 -> X87Word
  unary : X87UnaryOperation -> X87Word -> BitVec 16 -> X87Word
  binary : X87BinaryOperation -> X87Word -> X87Word -> BitVec 16 -> X87Word
  compare : X87Word -> X87Word -> BitVec 16 -> BitVec 3
  examine : X87Word -> BitVec 16 -> BitVec 16

def defaultX87Semantics : X87Semantics := {
  load := fun _ value _ => value
  store := fun _ value _ => value
  unary := fun _ value _ => value
  binary := fun _ left _ _ => left
  compare := fun _ _ _ => BitVec.ofNat 3 0
  examine := fun _ status => status
}

structure X87MachineState where
  stack : Nat -> X87Word := fun _ => BitVec.ofNat 80 0
  control : BitVec 16 := BitVec.ofNat 16 0x037f
  status : BitVec 16 := BitVec.ofNat 16 0
  semantics : X87Semantics := defaultX87Semantics

def readByte (bytes : Bytes) (offset : Nat) : Option Byte :=
  (bytes.drop offset).head?

def readU16 (bytes : Bytes) (offset : Nat) : Option Nat := do
  let b0 <- readByte bytes offset
  let b1 <- readByte bytes (offset + 1)
  if b0 < 256 && b1 < 256 then
    pure (b0 + b1 * 256)
  else
    none

def readU32 (bytes : Bytes) (offset : Nat) : Option Nat := do
  let lo <- readU16 bytes offset
  let hi <- readU16 bytes (offset + 2)
  pure (lo + hi * 65536)

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

inductive Reg where
  | eax | ebx | ecx | edx | esi | edi | ebp | esp
deriving Repr, DecidableEq

structure Registers (alpha : Type) where
  eax : alpha
  ebx : alpha
  ecx : alpha
  edx : alpha
  esi : alpha
  edi : alpha
  ebp : alpha
  esp : alpha
deriving Repr, DecidableEq

theorem Registers.eq_of_fields (original candidate : Registers alpha)
    (eax : original.eax = candidate.eax)
    (ebx : original.ebx = candidate.ebx)
    (ecx : original.ecx = candidate.ecx)
    (edx : original.edx = candidate.edx)
    (esi : original.esi = candidate.esi)
    (edi : original.edi = candidate.edi)
    (ebp : original.ebp = candidate.ebp)
    (esp : original.esp = candidate.esp) :
    original = candidate := by
  cases original
  cases candidate
  simp_all

def Registers.get (registers : Registers alpha) : Reg -> alpha
  | .eax => registers.eax
  | .ebx => registers.ebx
  | .ecx => registers.ecx
  | .edx => registers.edx
  | .esi => registers.esi
  | .edi => registers.edi
  | .ebp => registers.ebp
  | .esp => registers.esp

def Registers.set (registers : Registers alpha) (reg : Reg) (value : alpha) : Registers alpha :=
  match reg with
  | .eax => { registers with eax := value }
  | .ebx => { registers with ebx := value }
  | .ecx => { registers with ecx := value }
  | .edx => { registers with edx := value }
  | .esi => { registers with esi := value }
  | .edi => { registers with edi := value }
  | .ebp => { registers with ebp := value }
  | .esp => { registers with esp := value }

mutual
inductive Expr where
  | inputReg (reg : Reg)
  | inputFlagValue (bit : Nat)
  | inputFsBase
  | inputX87Control
  | inputX87Status
  | constant (value : Nat)
  | add (left right : Expr)
  | sub (left right : Expr)
  | bitAnd (left right : Expr)
  | bitXor (left right : Expr)
  | bitNot (value : Expr)
  | read8 (address : Expr)
  | read32 (address : Expr)
  | read8AfterWrite (address writeAddress writeValue prior : Expr)
  | extractByte (value : Expr) (index : Nat)
  | shiftLeft (value : Expr) (amount : Nat)
  | shiftRight (value : Expr) (amount : Nat)
  | shiftLeftBy (value amount : Expr)
  | shiftRightBy (value amount : Expr)
  | shiftArithmeticRightBy (value amount : Expr)
  | bitOr (left right : Expr)
  | ifEqual (left right thenValue elseValue : Expr)
  | unsignedLessValue (left right : Expr)
  | bitValue (value : Expr) (index : Nat)
  | multiply (left right : Expr)
  | multiplyHighUnsigned (left right : Expr)
  | multiplyHighSigned (left right : Expr)
  | divideQuotient (high low divisor : Expr)
  | divideRemainder (high low divisor : Expr)
  | divisionValidValue (high low divisor : Expr)
  | lowestSetBit (value : Expr)
  | highestSetBit (value : Expr)
  | undefined (slot : Nat)
  | x87Part (value : X87Expr) (part : Nat)
  | x87CompareBit (left right : X87Expr) (control : Expr) (bit : Nat)
  | x87ExamineStatus (value : X87Expr) (status : Expr)
deriving Repr, DecidableEq

inductive X87Expr where
  | inputStack (index : Nat)
  | load (format : X87LoadFormat) (address control : Expr)
  | imageLoad (format : X87LoadFormat) (raw : Nat) (control : Expr)
  | constant (value : Nat)
  | unary (operation : X87UnaryOperation) (value : X87Expr) (control : Expr)
  | binary (operation : X87BinaryOperation) (left right : X87Expr) (control : Expr)
  | store (format : X87StoreFormat) (value : X87Expr) (control : Expr)
deriving Repr, DecidableEq
end

mutual
def Expr.flagsWithin (allowed : List Nat) : Expr -> Bool
  | .inputReg _ | .inputFsBase | .inputX87Control | .inputX87Status | .constant _ |
      .undefined _ => true
  | .inputFlagValue bit => allowed.contains bit
  | .add left right | .sub left right | .bitAnd left right | .bitXor left right |
      .shiftLeftBy left right | .shiftRightBy left right |
      .shiftArithmeticRightBy left right | .bitOr left right |
      .unsignedLessValue left right | .multiply left right |
      .multiplyHighUnsigned left right | .multiplyHighSigned left right =>
      left.flagsWithin allowed && right.flagsWithin allowed
  | .bitNot value | .read8 value | .read32 value | .extractByte value _ |
      .shiftLeft value _ | .shiftRight value _ | .bitValue value _ |
      .lowestSetBit value | .highestSetBit value => value.flagsWithin allowed
  | .read8AfterWrite address writeAddress writeValue prior |
      .ifEqual address writeAddress writeValue prior =>
      address.flagsWithin allowed && writeAddress.flagsWithin allowed &&
        writeValue.flagsWithin allowed && prior.flagsWithin allowed
  | .divideQuotient high low divisor | .divideRemainder high low divisor |
      .divisionValidValue high low divisor =>
      high.flagsWithin allowed && low.flagsWithin allowed && divisor.flagsWithin allowed
  | .x87Part value _ => value.flagsWithin allowed
  | .x87CompareBit left right control _ =>
      left.flagsWithin allowed && right.flagsWithin allowed && control.flagsWithin allowed
  | .x87ExamineStatus value status =>
      value.flagsWithin allowed && status.flagsWithin allowed

def X87Expr.flagsWithin (allowed : List Nat) : X87Expr -> Bool
  | .inputStack _ | .constant _ => true
  | .load _ address control => address.flagsWithin allowed && control.flagsWithin allowed
  | .imageLoad _ _ control => control.flagsWithin allowed
  | .unary _ value control | .store _ value control =>
      value.flagsWithin allowed && control.flagsWithin allowed
  | .binary _ left right control =>
      left.flagsWithin allowed && right.flagsWithin allowed && control.flagsWithin allowed
end

def Expr.addNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant 0, expression => expression
  | .constant a, .constant b => .constant ((a + b) % (2 ^ 32))
  | .add expression (.constant a), .constant b =>
      .add expression (.constant ((a + b) % (2 ^ 32)))
  | .sub expression (.constant a), .constant b =>
      .add expression (.constant ((2 ^ 32 - a + b) % (2 ^ 32)))
  | a, b => .add a b

def Expr.subNormalized (left right : Expr) : Expr :=
  match left, right with
  | expression, .constant 0 => expression
  | .constant a, .constant b => .constant ((a + 2 ^ 32 - b) % (2 ^ 32))
  | a, b => .sub a b

def Expr.xorNormalized (left right : Expr) : Expr :=
  if left == right then .constant 0 else .bitXor left right

def Expr.signExtendNormalized (value : Expr) (bits : Nat) : Expr :=
  let mask := 2 ^ bits - 1
  let highMask := 2 ^ 32 - 1 - mask
  .ifEqual (.bitValue value (bits - 1)) (.constant 1)
    (.bitOr (.bitAnd value (.constant mask)) (.constant highMask))
    (.bitAnd value (.constant mask))

structure MachineState where
  registers : Registers Word
  memory : Memory
  undefinedValue : Nat -> Word := fun _ => BitVec.ofNat 32 0
  x87 : X87MachineState := {}
  eflags : Word := BitVec.ofNat 32 0
  fsBase : Word := BitVec.ofNat 32 0

structure MachineStateAgreement (allowedFlags : List Nat)
    (original candidate : MachineState) : Prop where
  registers : original.registers = candidate.registers
  memory : original.memory = candidate.memory
  undefinedValue : original.undefinedValue = candidate.undefinedValue
  x87 : original.x87 = candidate.x87
  fsBase : original.fsBase = candidate.fsBase
  flags : ∀ bit, allowedFlags.contains bit = true →
    original.eflags.extractLsb' bit 1 = candidate.eflags.extractLsb' bit 1

def MachineState.read32 (state : MachineState) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (state.memory address)
  let b1 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 := (BitVec.zeroExtend 32 (state.memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

def MachineState.readX87Word (state : MachineState) (address : Word) (size : Nat) : X87Word :=
  (List.range size).foldl (fun result index =>
    result ||| (BitVec.zeroExtend 80 (state.memory (address + BitVec.ofNat 32 index))).shiftLeft (index * 8))
    (BitVec.ofNat 80 0)

def lowestSetBitValue (value : Word) : Nat -> Nat -> Word
  | _, 0 => BitVec.ofNat 32 32
  | index, fuel + 1 =>
      if Nat.testBit value.toNat index then BitVec.ofNat 32 index
      else lowestSetBitValue value (index + 1) fuel

def highestSetBitValue (value : Word) : Nat -> Nat -> Word
  | _, 0 => BitVec.ofNat 32 0
  | index, fuel + 1 =>
      if Nat.testBit value.toNat index then BitVec.ofNat 32 index
      else highestSetBitValue value (index - 1) fuel

def read8AfterWriteValue (address writeAddress writeValue prior : Word) : Word :=
  if address = writeAddress then BitVec.zeroExtend 32 (writeValue.extractLsb' 0 8)
  else if address = writeAddress + BitVec.ofNat 32 1 then
    BitVec.zeroExtend 32 (writeValue.extractLsb' 8 8)
  else if address = writeAddress + BitVec.ofNat 32 2 then
    BitVec.zeroExtend 32 (writeValue.extractLsb' 16 8)
  else if address = writeAddress + BitVec.ofNat 32 3 then
    BitVec.zeroExtend 32 (writeValue.extractLsb' 24 8)
  else prior

mutual
def Expr.eval (state : MachineState) : Expr -> Word
  | .inputReg reg => state.registers.get reg
  | .inputFlagValue bit =>
      if state.eflags.extractLsb' bit 1 == BitVec.ofNat 1 1 then
        BitVec.ofNat 32 1
      else
        BitVec.ofNat 32 0
  | .inputFsBase => state.fsBase
  | .inputX87Control => BitVec.zeroExtend 32 state.x87.control
  | .inputX87Status => BitVec.zeroExtend 32 state.x87.status
  | .constant value => BitVec.ofNat 32 value
  | .add left right => left.eval state + right.eval state
  | .sub left right => left.eval state - right.eval state
  | .bitAnd left right => left.eval state &&& right.eval state
  | .bitXor left right => left.eval state ^^^ right.eval state
  | .bitNot value => ~~~(value.eval state)
  | .read8 address => BitVec.zeroExtend 32 (state.memory (address.eval state))
  | .read32 address => state.read32 (address.eval state)
  | .read8AfterWrite address writeAddress writeValue prior =>
      read8AfterWriteValue (address.eval state) (writeAddress.eval state)
        (writeValue.eval state) (prior.eval state)
  | .extractByte value index => BitVec.zeroExtend 32 ((value.eval state).extractLsb' (index * 8) 8)
  | .shiftLeft value amount => (value.eval state).shiftLeft amount
  | .shiftRight value amount => (value.eval state).ushiftRight amount
  | .shiftLeftBy value amount => (value.eval state).shiftLeft ((amount.eval state).toNat % 32)
  | .shiftRightBy value amount => (value.eval state).ushiftRight ((amount.eval state).toNat % 32)
  | .shiftArithmeticRightBy value amount => (value.eval state).sshiftRight ((amount.eval state).toNat % 32)
  | .bitOr left right => left.eval state ||| right.eval state
  | .ifEqual left right thenValue elseValue =>
      if left.eval state = right.eval state then thenValue.eval state else elseValue.eval state
  | .unsignedLessValue left right =>
      if left.eval state < right.eval state then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .bitValue value index =>
      if Nat.testBit (value.eval state).toNat index then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .multiply left right => left.eval state * right.eval state
  | .multiplyHighUnsigned left right =>
      let product := BitVec.zeroExtend 64 (left.eval state) * BitVec.zeroExtend 64 (right.eval state)
      product.extractLsb' 32 32
  | .multiplyHighSigned left right =>
      let product := BitVec.signExtend 64 (left.eval state) * BitVec.signExtend 64 (right.eval state)
      product.extractLsb' 32 32
  | .divideQuotient high low divisor =>
      let dividend := (BitVec.zeroExtend 64 (high.eval state)).shiftLeft 32 |||
        BitVec.zeroExtend 64 (low.eval state)
      let divisor := BitVec.zeroExtend 64 (divisor.eval state)
      (dividend / divisor).extractLsb' 0 32
  | .divideRemainder high low divisor =>
      let dividend := (BitVec.zeroExtend 64 (high.eval state)).shiftLeft 32 |||
        BitVec.zeroExtend 64 (low.eval state)
      let divisor := BitVec.zeroExtend 64 (divisor.eval state)
      (dividend % divisor).extractLsb' 0 32
  | .divisionValidValue high low divisor =>
      let divisorValue := divisor.eval state
      if divisorValue == BitVec.ofNat 32 0 then BitVec.ofNat 32 0 else
      let dividend := (BitVec.zeroExtend 64 (high.eval state)).shiftLeft 32 |||
        BitVec.zeroExtend 64 (low.eval state)
      let quotient := dividend / BitVec.zeroExtend 64 divisorValue
      if quotient < BitVec.ofNat 64 (2 ^ 32) then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .lowestSetBit value => lowestSetBitValue (value.eval state) 0 32
  | .highestSetBit value => highestSetBitValue (value.eval state) 31 32
  | .undefined slot => state.undefinedValue slot
  | .x87Part value part =>
      let evaluated := value.eval state
      if part == 2 then
        BitVec.zeroExtend 32 (evaluated.extractLsb' 64 16)
      else
        evaluated.extractLsb' (part * 32) 32
  | .x87CompareBit left right control bit =>
      let control := (control.eval state).extractLsb' 0 16
      let compared := state.x87.semantics.compare (left.eval state) (right.eval state) control
      if Nat.testBit compared.toNat bit then BitVec.ofNat 32 1 else BitVec.ofNat 32 0
  | .x87ExamineStatus value status =>
      BitVec.zeroExtend 32 (state.x87.semantics.examine (value.eval state)
        ((status.eval state).extractLsb' 0 16))

def X87Expr.eval (state : MachineState) : X87Expr -> X87Word
  | .inputStack index => state.x87.stack index
  | .load format address control =>
      state.x87.semantics.load format (state.readX87Word (address.eval state) format.byteWidth)
        ((control.eval state).extractLsb' 0 16)
  | .imageLoad format raw control =>
      state.x87.semantics.load format (BitVec.ofNat 80 raw)
        ((control.eval state).extractLsb' 0 16)
  | .constant value => BitVec.ofNat 80 value
  | .unary operation value control =>
      state.x87.semantics.unary operation (value.eval state) ((control.eval state).extractLsb' 0 16)
  | .binary operation left right control =>
      state.x87.semantics.binary operation (left.eval state) (right.eval state)
        ((control.eval state).extractLsb' 0 16)
  | .store format value control =>
      state.x87.semantics.store format (value.eval state) ((control.eval state).extractLsb' 0 16)
end

theorem Expr.eval_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (expression : Expr)
    (within : expression.flagsWithin allowed = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    expression.eval original = expression.eval candidate := by
  rcases agreement with ⟨registers, memory, undefinedValue, x87, fsBase, flags⟩
  have evalAll : ∀ value : Expr, value.flagsWithin allowed = true →
      value.eval original = value.eval candidate := by
    intro value
    apply Expr.rec
      (motive_1 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate)
      (motive_2 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate) <;>
      simp_all [Expr.flagsWithin, X87Expr.flagsWithin, Expr.eval, X87Expr.eval,
        MachineState.read32, MachineState.readX87Word]
  exact evalAll expression within

theorem X87Expr.eval_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (expression : X87Expr)
    (within : expression.flagsWithin allowed = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    expression.eval original = expression.eval candidate := by
  rcases agreement with ⟨registers, memory, undefinedValue, x87, fsBase, flags⟩
  have evalAll : ∀ value : X87Expr, value.flagsWithin allowed = true →
      value.eval original = value.eval candidate := by
    intro value
    apply X87Expr.rec
      (motive_1 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate)
      (motive_2 := fun item => item.flagsWithin allowed = true →
        item.eval original = item.eval candidate) <;>
      simp_all [Expr.flagsWithin, X87Expr.flagsWithin, Expr.eval, X87Expr.eval,
        MachineState.read32, MachineState.readX87Word]
  exact evalAll expression within

inductive BoolExpr where
  | equal (left right : Expr)
  | not (value : BoolExpr)
  | and (left right : BoolExpr)
  | or (left right : BoolExpr)
  | xor (left right : BoolExpr)
  | unsignedLess (left right : Expr)
  | msb (value : Expr)
  | bit (value : Expr) (index : Nat)
  | inputFlag (index : Nat)
  | divisionValid (high low divisor : Expr)
deriving Repr, DecidableEq

def BoolExpr.flagsWithin (allowed : List Nat) : BoolExpr -> Bool
  | .equal left right | .unsignedLess left right =>
      left.flagsWithin allowed && right.flagsWithin allowed
  | .not value => value.flagsWithin allowed
  | .and left right | .or left right | .xor left right =>
      left.flagsWithin allowed && right.flagsWithin allowed
  | .msb value => value.flagsWithin allowed
  | .bit value _ => value.flagsWithin allowed
  | .inputFlag index => allowed.contains index
  | .divisionValid high low divisor =>
      high.flagsWithin allowed && low.flagsWithin allowed && divisor.flagsWithin allowed

def BoolExpr.toWord : BoolExpr -> Expr
  | .equal left right => .ifEqual left right (.constant 1) (.constant 0)
  | .not value => .ifEqual value.toWord (.constant 0) (.constant 1) (.constant 0)
  | .and left right => .bitAnd left.toWord right.toWord
  | .or left right => .bitOr left.toWord right.toWord
  | .xor left right => .bitXor left.toWord right.toWord
  | .unsignedLess left right => .unsignedLessValue left right
  | .msb value => .bitValue value 31
  | .bit value index => .bitValue value index
  | .inputFlag flagIndex => .inputFlagValue flagIndex
  | .divisionValid high low divisor => .divisionValidValue high low divisor

def BoolExpr.eval (state : MachineState) : BoolExpr -> Bool
  | .equal left right => decide (left.eval state = right.eval state)
  | .not value => !(value.eval state)
  | .and left right => left.eval state && right.eval state
  | .or left right => left.eval state || right.eval state
  | .xor left right => left.eval state != right.eval state
  | .unsignedLess left right => decide (left.eval state < right.eval state)
  | .msb value => Nat.testBit (value.eval state).toNat 31
  | .bit value index => Nat.testBit (value.eval state).toNat index
  | .inputFlag flagIndex =>
      state.eflags.extractLsb' flagIndex 1 == BitVec.ofNat 1 1
  | .divisionValid high low divisor =>
      (Expr.divisionValidValue high low divisor).eval state == BitVec.ofNat 32 1

theorem BoolExpr.eval_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (expression : BoolExpr)
    (within : expression.flagsWithin allowed = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    expression.eval original = expression.eval candidate := by
  have evalExpr := fun value safe =>
    Expr.eval_eq_of_flagsWithin allowed original candidate value safe agreement
  have evalFlag := agreement.flags
  induction expression <;>
    simp_all [BoolExpr.flagsWithin, BoolExpr.eval]
  case divisionValid high low divisor =>
    have evaluated := evalExpr (.divisionValidValue high low divisor) (by
      simp [Expr.flagsWithin, *])
    exact congrArg (fun value => value == BitVec.ofNat 32 1) evaluated

structure FlagsExpr where
  zero : Option BoolExpr
  carry : Option BoolExpr
  auxiliary : Option BoolExpr := none
  sign : Option BoolExpr
  overflow : Option BoolExpr
  parity : Option BoolExpr
deriving Repr, DecidableEq

def updateFlag (word : Word) (index : Nat) : Option Bool -> Word
  | none => word
  | some value =>
      if value then
        word ||| BitVec.ofNat 32 (2 ^ index)
      else
        word &&& ~~~(BitVec.ofNat 32 (2 ^ index))

def FlagsExpr.eval (state : MachineState) (flags : FlagsExpr) : Word :=
  let carry := updateFlag state.eflags 0 (flags.carry.map (BoolExpr.eval state))
  let parity := updateFlag carry 2 (flags.parity.map (BoolExpr.eval state))
  let auxiliary := updateFlag parity 4 (flags.auxiliary.map (BoolExpr.eval state))
  let zero := updateFlag auxiliary 6 (flags.zero.map (BoolExpr.eval state))
  let sign := updateFlag zero 7 (flags.sign.map (BoolExpr.eval state))
  updateFlag sign 11 (flags.overflow.map (BoolExpr.eval state))

theorem updateFlag_extract_preserved (word : Word) (updated observed : Nat)
    (value : Option Bool)
    (setMask : (BitVec.ofNat 32 (2 ^ updated)).extractLsb' observed 1 = 0#1)
    (clearMask : (~~~(BitVec.ofNat 32 (2 ^ updated))).extractLsb' observed 1 =
      BitVec.allOnes 1) :
    (updateFlag word updated value).extractLsb' observed 1 =
      word.extractLsb' observed 1 := by
  cases value with
  | none => rfl
  | some value =>
      cases value with
      | false =>
          change (word &&& ~~~(BitVec.ofNat 32 (2 ^ updated))).extractLsb' observed 1 = _
          rw [BitVec.extractLsb'_and, clearMask, BitVec.and_allOnes]
      | true =>
          change (word ||| BitVec.ofNat 32 (2 ^ updated)).extractLsb' observed 1 = _
          rw [BitVec.extractLsb'_or, setMask, BitVec.or_zero]

theorem updateFlag_extract_assigned (word : Word) (index : Nat) (value : Option Bool)
    (setMask : (BitVec.ofNat 32 (2 ^ index)).extractLsb' index 1 = BitVec.allOnes 1)
    (clearMask : (~~~(BitVec.ofNat 32 (2 ^ index))).extractLsb' index 1 = 0#1) :
    (updateFlag word index value).extractLsb' index 1 =
      match value with
      | none => word.extractLsb' index 1
      | some false => 0#1
      | some true => BitVec.allOnes 1 := by
  cases value with
  | none => rfl
  | some value =>
      cases value with
      | false =>
          change (word &&& ~~~(BitVec.ofNat 32 (2 ^ index))).extractLsb' index 1 = 0#1
          rw [BitVec.extractLsb'_and, clearMask, BitVec.and_zero]
      | true =>
          change (word ||| BitVec.ofNat 32 (2 ^ index)).extractLsb' index 1 =
            BitVec.allOnes 1
          rw [BitVec.extractLsb'_or, setMask, BitVec.or_allOnes]

def evalFlagBit (state : MachineState) (index : Nat) : Option BoolExpr -> BitVec 1
  | none => state.eflags.extractLsb' index 1
  | some value => if value.eval state then BitVec.allOnes 1 else 0#1

def flagValueWithin (allowed : List Nat) (index : Nat) : Option BoolExpr -> Bool
  | none => allowed.contains index
  | some value => value.flagsWithin allowed

theorem evalFlagBit_eq_of_flagsWithin (allowed : List Nat) (index : Nat)
    (original candidate : MachineState) (value : Option BoolExpr)
    (within : flagValueWithin allowed index value = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    evalFlagBit original index value = evalFlagBit candidate index value := by
  cases value with
  | none =>
      simpa [flagValueWithin, evalFlagBit] using agreement.flags index within
  | some expression =>
      have evaluated := BoolExpr.eval_eq_of_flagsWithin allowed original candidate
        expression within agreement
      simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_cf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 0 1 = evalFlagBit state 0 flags.carry := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 0 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 0 _ (by decide) (by decide)]
  cases carry : flags.carry with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_pf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 2 1 = evalFlagBit state 2 flags.parity := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 2 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 2 _ (by decide) (by decide)]
  cases parity : flags.parity with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_af (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 4 1 = evalFlagBit state 4 flags.auxiliary := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 4 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 4 _ (by decide) (by decide)]
  cases auxiliary : flags.auxiliary with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_zf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 6 1 = evalFlagBit state 6 flags.zero := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 6 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 6 _ (by decide) (by decide)]
  cases zero : flags.zero with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_sf (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 7 1 = evalFlagBit state 7 flags.sign := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_assigned _ 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 7 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 7 _ (by decide) (by decide)]
  cases sign : flags.sign with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

@[simp] theorem FlagsExpr.eval_extract_df (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 10 1 = state.eflags.extractLsb' 10 1 := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_preserved _ 11 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 10 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 10 _ (by decide) (by decide)]

@[simp] theorem FlagsExpr.eval_extract_of (state : MachineState) (flags : FlagsExpr) :
    (flags.eval state).extractLsb' 11 1 = evalFlagBit state 11 flags.overflow := by
  unfold FlagsExpr.eval
  rw [updateFlag_extract_assigned _ 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 7 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 6 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 4 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 2 11 _ (by decide) (by decide)]
  rw [updateFlag_extract_preserved _ 0 11 _ (by decide) (by decide)]
  cases overflow : flags.overflow with
  | none => rfl
  | some value => cases evaluated : value.eval state <;> simp [evalFlagBit, evaluated]

theorem FlagsExpr.eval_cf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 0 flags.carry = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 0 1 = (flags.eval candidate).extractLsb' 0 1 := by
  simpa only [FlagsExpr.eval_extract_cf] using
    evalFlagBit_eq_of_flagsWithin allowed 0 original candidate flags.carry within agreement

theorem FlagsExpr.eval_pf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 2 flags.parity = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 2 1 = (flags.eval candidate).extractLsb' 2 1 := by
  simpa only [FlagsExpr.eval_extract_pf] using
    evalFlagBit_eq_of_flagsWithin allowed 2 original candidate flags.parity within agreement

theorem FlagsExpr.eval_af_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 4 flags.auxiliary = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 4 1 = (flags.eval candidate).extractLsb' 4 1 := by
  simpa only [FlagsExpr.eval_extract_af] using
    evalFlagBit_eq_of_flagsWithin allowed 4 original candidate flags.auxiliary within agreement

theorem FlagsExpr.eval_zf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 6 flags.zero = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 6 1 = (flags.eval candidate).extractLsb' 6 1 := by
  simpa only [FlagsExpr.eval_extract_zf] using
    evalFlagBit_eq_of_flagsWithin allowed 6 original candidate flags.zero within agreement

theorem FlagsExpr.eval_sf_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 7 flags.sign = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 7 1 = (flags.eval candidate).extractLsb' 7 1 := by
  simpa only [FlagsExpr.eval_extract_sf] using
    evalFlagBit_eq_of_flagsWithin allowed 7 original candidate flags.sign within agreement

theorem FlagsExpr.eval_df_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : allowed.contains 10 = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 10 1 = (flags.eval candidate).extractLsb' 10 1 := by
  simpa only [FlagsExpr.eval_extract_df] using agreement.flags 10 within

theorem FlagsExpr.eval_of_eq_of_flagsWithin (allowed : List Nat)
    (original candidate : MachineState) (flags : FlagsExpr)
    (within : flagValueWithin allowed 11 flags.overflow = true)
    (agreement : MachineStateAgreement allowed original candidate) :
    (flags.eval original).extractLsb' 11 1 = (flags.eval candidate).extractLsb' 11 1 := by
  simpa only [FlagsExpr.eval_extract_of] using
    evalFlagBit_eq_of_flagsWithin allowed 11 original candidate flags.overflow within agreement

structure SymbolicX87State where
  stack : List X87Expr
  control : Expr
  status : Expr
deriving Repr, DecidableEq

def initialSymbolicX87 : SymbolicX87State := {
  stack := (List.range 8).map X87Expr.inputStack
  control := .inputX87Control
  status := .inputX87Status
}

def SymbolicX87State.get (state : SymbolicX87State) (index : Nat) : Option X87Expr :=
  (state.stack.drop index).head?

def SymbolicX87State.set (state : SymbolicX87State) (index : Nat) (value : X87Expr) : Option SymbolicX87State :=
  if index < state.stack.length then
    some { state with stack := (state.stack.take index) ++ [value] ++ (state.stack.drop (index + 1)) }
  else
    none

def SymbolicX87State.push (state : SymbolicX87State) (value : X87Expr) : SymbolicX87State :=
  { state with stack := value :: state.stack }

def SymbolicX87State.pop (state : SymbolicX87State) : Option SymbolicX87State := do
  let _ <- state.stack.head?
  pure { state with stack := state.stack.drop 1 }

def parityExpression (result : Expr) : BoolExpr :=
  .not (.xor (.bit result 0)
    (.xor (.bit result 1)
      (.xor (.bit result 2)
        (.xor (.bit result 3)
          (.xor (.bit result 4)
            (.xor (.bit result 5) (.xor (.bit result 6) (.bit result 7))))))))

def auxiliaryCarryExpression (left right result : Expr) : BoolExpr :=
  .bit (.bitXor (.bitXor left right) result) 4

def subtractionFlags (left right result : Expr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.unsignedLess left right)
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.xor (.msb left) (.msb right)) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

def additionFlags (left right result : Expr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.unsignedLess result left)
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.not (.xor (.msb left) (.msb right))) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

def logicalFlags (undefinedSlot : Nat) (result : Expr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.equal (.constant 0) (.constant 1))
  auxiliary := some (.bit (.undefined undefinedSlot) 0)
  sign := some (.msb result)
  overflow := some (.equal (.constant 0) (.constant 1))
  parity := some (parityExpression result)
}

def subtractionFlagsWidth (bits : Nat) (left right result : Expr) : FlagsExpr :=
  let mask := .constant (2 ^ bits - 1)
  let left := .bitAnd left mask
  let right := .bitAnd right mask
  let result := .bitAnd result mask
  {
    zero := some (.equal result (.constant 0))
    carry := some (.unsignedLess left right)
    auxiliary := some (auxiliaryCarryExpression left right result)
    sign := some (.bit result (bits - 1))
    overflow := some (.and (.xor (.bit left (bits - 1)) (.bit right (bits - 1)))
      (.xor (.bit left (bits - 1)) (.bit result (bits - 1))))
    parity := some (parityExpression result)
  }

def additionFlagsWidth (bits : Nat) (left right result : Expr) : FlagsExpr :=
  let mask := .constant (2 ^ bits - 1)
  let left := .bitAnd left mask
  let right := .bitAnd right mask
  let result := .bitAnd result mask
  {
    zero := some (.equal result (.constant 0))
    carry := some (.unsignedLess result left)
    auxiliary := some (auxiliaryCarryExpression left right result)
    sign := some (.bit result (bits - 1))
    overflow := some (.and (.not (.xor (.bit left (bits - 1)) (.bit right (bits - 1))))
      (.xor (.bit left (bits - 1)) (.bit result (bits - 1))))
    parity := some (parityExpression result)
  }

def logicalFlagsWidth (undefinedSlot bits : Nat) (result : Expr) : FlagsExpr :=
  let result := .bitAnd result (.constant (2 ^ bits - 1))
  {
    zero := some (.equal result (.constant 0))
    carry := some (.equal (.constant 0) (.constant 1))
    auxiliary := some (.bit (.undefined undefinedSlot) 0)
    sign := some (.bit result (bits - 1))
    overflow := some (.equal (.constant 0) (.constant 1))
    parity := some (parityExpression result)
  }

def adcFlags (left right result : Expr) (carryIn : BoolExpr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.or (.unsignedLess result left) (.and carryIn (.equal result left)))
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.not (.xor (.msb left) (.msb right))) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

def sbbFlags (left right result : Expr) (borrowIn : BoolExpr) : FlagsExpr := {
  zero := some (.equal result (.constant 0))
  carry := some (.or (.unsignedLess left right) (.and borrowIn (.equal left right)))
  auxiliary := some (auxiliaryCarryExpression left right result)
  sign := some (.msb result)
  overflow := some (.and (.xor (.msb left) (.msb right)) (.xor (.msb left) (.msb result)))
  parity := some (parityExpression result)
}

structure BulkCopyExpr where
  destination : Expr
  source : Expr
  count : Expr
  direction : BoolExpr
deriving Repr, DecidableEq

inductive OutcomeExpr where
  | returned (target : Expr)
  | jump (targetRva : Nat)
  | branch (condition : BoolExpr) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Expr) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Expr)
  | bulkCopy (copy : BulkCopyExpr) (continuationRva : Nat)
  | indirectCall (target : Expr) (continuationRva returnAddress : Nat)
  | indirectJump (target : Expr)
  | checkedContinue (valid : BoolExpr) (continuationRva : Nat)
  | atomicCompareExchange (address expected replacement : Expr) (continuationRva : Nat)
deriving Repr, DecidableEq

structure SymbolicBehavior where
  registers : Registers Expr
  x87 : SymbolicX87State
  writes : List (Expr × Expr)
  comparison : Option (Expr × Expr)
  flags : Option FlagsExpr
  outcome : Option OutcomeExpr
deriving Repr, DecidableEq

structure ConcreteX87State where
  stack : List X87Word
  control : BitVec 16
  status : BitVec 16
deriving Repr, DecidableEq

inductive ConcreteOutcome where
  | returned (target : Word)
  | jump (targetRva : Nat)
  | branch (condition : Bool) (trueTargetRva falseTargetRva : Nat)
  | call (targetRva returnRva returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Word) (returnRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Word)
  | bulkCopy (destination source count : Word) (direction : Bool) (continuationRva : Nat)
  | indirectCall (target : Word) (continuationRva returnAddress : Nat)
  | indirectJump (target : Word)
  | checkedContinue (valid : Bool) (continuationRva : Nat)
  | atomicCompareExchange (address expected replacement : Word) (continuationRva : Nat)

structure ConcreteBehavior where
  registers : Registers Word
  x87 : ConcreteX87State
  memory : Memory
  eflags : Word
  outcome : Option ConcreteOutcome

def initialSymbolic : SymbolicBehavior := {
  registers := {
    eax := .inputReg .eax,
    ebx := .inputReg .ebx,
    ecx := .inputReg .ecx,
    edx := .inputReg .edx,
    esi := .inputReg .esi,
    edi := .inputReg .edi,
    ebp := .inputReg .ebp,
    esp := .inputReg .esp,
  },
  x87 := initialSymbolicX87,
  writes := [],
  comparison := none,
  flags := some {
    zero := some (.inputFlag 6)
    carry := some (.inputFlag 0)
    sign := some (.inputFlag 7)
    overflow := some (.inputFlag 11)
    parity := some (.inputFlag 2)
  },
  outcome := none,
}

def Memory.write32 (memory : Memory) (address value : Word) : Memory :=
  fun query =>
    if query = address then value.extractLsb' 0 8
    else if query = address + BitVec.ofNat 32 1 then value.extractLsb' 8 8
    else if query = address + BitVec.ofNat 32 2 then value.extractLsb' 16 8
    else if query = address + BitVec.ofNat 32 3 then value.extractLsb' 24 8
    else memory query

def applyWrites (state : MachineState) (writes : List (Expr × Expr)) : Memory :=
  writes.foldl (fun memory write => memory.write32 (write.1.eval state) (write.2.eval state)) state.memory

def Expr.offset (address : Expr) (amount : Nat) : Expr :=
  Expr.addNormalized address (.constant amount)

def Expr.affineBaseOffset : Expr -> Expr × Nat
  | .add base (.constant offset) => (base, offset % (2 ^ 32))
  | .sub base (.constant offset) => (base, (2 ^ 32 - offset) % (2 ^ 32))
  | expression => (expression, 0)

def Expr.provablyUnequal (left right : Expr) : Bool :=
  let leftAffine := left.affineBaseOffset
  let rightAffine := right.affineBaseOffset
  leftAffine.1 == rightAffine.1 && leftAffine.2 != rightAffine.2

def symbolicRead8 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  behavior.writes.foldl (fun current write =>
    let offsets := [0, 1, 2, 3]
    match offsets.find? (fun index => address == write.1.offset index) with
    | some index => .extractByte write.2 index
    | none =>
        if offsets.all (fun index => address.provablyUnequal (write.1.offset index)) then current
        else .read8AfterWrite address write.1 write.2 current) (.read8 address)

def symbolicRead32 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  if behavior.writes.isEmpty then
    .read32 address
  else
    let b0 := symbolicRead8 behavior address
    let b1 := .shiftLeft (symbolicRead8 behavior (address.offset 1)) 8
    let b2 := .shiftLeft (symbolicRead8 behavior (address.offset 2)) 16
    let b3 := .shiftLeft (symbolicRead8 behavior (address.offset 3)) 24
    .bitOr (.bitOr b0 b1) (.bitOr b2 b3)

def symbolicRead16 (behavior : SymbolicBehavior) (address : Expr) : Expr :=
  let b0 := symbolicRead8 behavior address
  let b1 := .shiftLeft (symbolicRead8 behavior (address.offset 1)) 8
  .bitOr b0 b1

def SymbolicBehavior.write32 (behavior : SymbolicBehavior) (address value : Expr) : SymbolicBehavior :=
  { behavior with writes := behavior.writes ++ [(address, value)] }

def SymbolicBehavior.eval (behavior : SymbolicBehavior) (state : MachineState) : ConcreteBehavior := {
  registers := {
    eax := behavior.registers.eax.eval state,
    ebx := behavior.registers.ebx.eval state,
    ecx := behavior.registers.ecx.eval state,
    edx := behavior.registers.edx.eval state,
    esi := behavior.registers.esi.eval state,
    edi := behavior.registers.edi.eval state,
    ebp := behavior.registers.ebp.eval state,
    esp := behavior.registers.esp.eval state,
  },
  x87 := {
    stack := behavior.x87.stack.map (X87Expr.eval state)
    control := (behavior.x87.control.eval state).extractLsb' 0 16
    status := (behavior.x87.status.eval state).extractLsb' 0 16
  },
  memory := applyWrites state behavior.writes,
  eflags := behavior.flags.map (FlagsExpr.eval state) |>.getD state.eflags
  outcome := behavior.outcome.map (fun outcome =>
    match outcome with
    | .returned target => .returned (target.eval state)
    | .jump targetRva => .jump targetRva
    | .branch condition trueTargetRva falseTargetRva =>
        .branch (condition.eval state) trueTargetRva falseTargetRva
    | .call targetRva returnRva returnAddress => .call targetRva returnRva returnAddress
    | .externalCall imported arguments returnRva =>
        .externalCall imported (arguments.map (Expr.eval state)) returnRva
    | .externalJump imported arguments =>
        .externalJump imported (arguments.map (Expr.eval state))
    | .bulkCopy copy continuationRva =>
        .bulkCopy (copy.destination.eval state) (copy.source.eval state) (copy.count.eval state)
          (copy.direction.eval state) continuationRva
    | .indirectCall target continuationRva returnAddress =>
        .indirectCall (target.eval state) continuationRva returnAddress
    | .indirectJump target => .indirectJump (target.eval state)
    | .checkedContinue valid continuationRva => .checkedContinue (valid.eval state) continuationRva
    | .atomicCompareExchange address expected replacement continuationRva =>
        .atomicCompareExchange (address.eval state) (expected.eval state) (replacement.eval state)
          continuationRva),
}

def readImmediate32 (bytes : Bytes) : Option Nat :=
  readU32 bytes 0

def signExtendImmediate8 (byte : Nat) : Nat :=
  if byte < 128 then byte else 2 ^ 32 - (256 - byte)

def relativeTarget8 (nextRva byte : Nat) : Nat :=
  if byte < 128 then nextRva + byte else nextRva - (256 - byte)

def relativeTarget32 (nextRva displacement : Nat) : Nat :=
  if displacement < 2 ^ 31 then nextRva + displacement else nextRva - (2 ^ 32 - displacement)

structure Addressing where
  base : Option Reg
  index : Option Reg
  scaleShift : Nat
  displacement : Nat
deriving Repr, DecidableEq

inductive Operand32 where
  | register (reg : Reg)
  | memory (addressing : Addressing)
  | immediate (value : Nat)
deriving Repr, DecidableEq

inductive OperandWidth where
  | byte
  | word
deriving Repr, DecidableEq

def OperandWidth.bits : OperandWidth -> Nat
  | .byte => 8
  | .word => 16

structure ByteRegister where
  parent : Reg
  high : Bool
deriving Repr, DecidableEq

inductive Operand8 where
  | register (reg : ByteRegister)
  | memory (addressing : Addressing)
  | immediate (value : Nat)
deriving Repr, DecidableEq

inductive BinaryOperation where
  | add
  | sub
  | xor
  | and
  | or
  | compare
  | test
deriving Repr, DecidableEq

inductive Condition where
  | overflow
  | notOverflow
  | equal
  | notEqual
  | below
  | aboveOrEqual
  | belowOrEqual
  | above
  | sign
  | notSign
  | parity
  | notParity
  | less
  | greaterOrEqual
  | greater
  | lessOrEqual
deriving Repr, DecidableEq

def conditionOfCode : Nat -> Option Condition
  | 0x0 => some .overflow
  | 0x1 => some .notOverflow
  | 0x2 => some .below
  | 0x3 => some .aboveOrEqual
  | 0x4 => some .equal
  | 0x5 => some .notEqual
  | 0x6 => some .belowOrEqual
  | 0x7 => some .above
  | 0x8 => some .sign
  | 0x9 => some .notSign
  | 0xa => some .parity
  | 0xb => some .notParity
  | 0xc => some .less
  | 0xd => some .greaterOrEqual
  | 0xe => some .lessOrEqual
  | 0xf => some .greater
  | _ => none

inductive ShiftOperation where
  | left
  | right
  | arithmeticRight
deriving Repr, DecidableEq

inductive ShiftCount where
  | immediate (value : Nat)
  | cl
deriving Repr, DecidableEq

inductive UnaryOperation where
  | bitNot
  | negate
deriving Repr, DecidableEq

inductive Instruction where
  | nop
  | ret
  | retPop (bytes : Nat)
  | movRegImm (destination : Reg) (value : Nat)
  | movRegReg (destination source : Reg)
  | addZero (destination : Reg)
  | subZero (destination : Reg)
  | cmpImm (source : Reg) (value : Nat)
  | branchEqual (inverted : Bool) (displacement : Nat)
  | jumpRel8 (displacement : Nat)
  | jumpRel32 (displacement : Nat)
  | pushReg (source : Reg)
  | popReg (destination : Reg)
  | leave
  | lea (destination base : Reg) (offset : Nat)
  | load32 (destination base : Reg) (offset : Nat)
  | store32 (base : Reg) (offset : Nat) (source : Reg)
  | zeroReg (destination : Reg)
  | callRel32 (displacement : Nat)
  | callImport (absoluteAddress : Nat)
  | jumpImport (absoluteAddress : Nat)
  | movFromOperand (destination : Reg) (source : Operand32)
  | movToOperand (destination : Operand32) (source : Reg)
  | movImmediate (destination : Operand32) (value : Nat)
  | leaAddress (destination : Reg) (source : Addressing)
  | binary (operation : BinaryOperation) (destination source : Operand32)
  | shift (operation : ShiftOperation) (destination : Operand32) (count : ShiftCount)
  | unary (operation : UnaryOperation) (destination : Operand32)
  | branchCondition (condition : Condition) (displacement size : Nat)
  | movZeroExtend (destination : Reg) (source : Operand32) (width : Nat)
  | movSignExtend (destination : Reg) (source : Operand32) (width : Nat)
  | movFromOperandWidth (width : OperandWidth) (destination : Reg) (source : Operand32)
  | movToOperandWidth (width : OperandWidth) (destination : Operand32) (source : Reg)
  | movImmediateWidth (width : OperandWidth) (destination : Operand32) (value : Nat)
  | binaryWidth (width : OperandWidth) (operation : BinaryOperation) (destination source : Operand32)
  | movFromOperand8 (destination : ByteRegister) (source : Operand8)
  | movToOperand8 (destination : Operand8) (source : ByteRegister)
  | movImmediate8 (destination : Operand8) (value : Nat)
  | binary8 (operation : BinaryOperation) (destination source : Operand8)
  | conditionalMove (condition : Condition) (destination : Reg) (source : Operand32)
  | setCondition (condition : Condition) (destination : Operand8)
  | exchange (destination : Operand32) (source : Reg)
  | convertWordToDword
  | convertDwordToQuad
  | binaryCarry (subtract : Bool) (destination source : Operand32)
  | multiplyFull (signed : Bool) (source : Operand32)
  | multiplyLow (destination : Reg) (source : Operand32) (immediate : Option Nat)
  | doubleShift (left : Bool) (destination : Operand32) (source : Reg) (count : ShiftCount)
  | bitScan (reverse : Bool) (destination : Reg) (source : Operand32)
  | x87LoadStack (index : Nat)
  | x87LoadConstant (value : Nat)
  | x87Exchange (index : Nat)
  | x87StoreStack (index : Nat) (pop : Bool)
  | x87Unary (operation : X87UnaryOperation)
  | x87BinaryStack (operation : X87BinaryOperation) (destination source : Nat) (pop : Bool)
  | x87CompareStack (index : Nat) (pop : Bool)
  | x87LoadMemory (format : X87LoadFormat) (source : Addressing)
  | x87StoreMemory (format : X87StoreFormat) (destination : Addressing) (pop : Bool)
  | x87BinaryMemory (operation : X87BinaryOperation) (format : X87LoadFormat) (source : Addressing)
  | x87LoadControl (source : Addressing)
  | x87StoreControl (destination : Addressing)
  | x87Initialize
  | x87StoreStatusAx
  | x87Examine
  | moveDwords (repeated : Bool)
  | callIndirect (target : Operand32)
  | jumpIndirect (target : Operand32)
  | pushOperand (source : Operand32)
  | movFs32 (destination : Reg) (source : Addressing)
  | divideUnsigned (source : Operand32)
  | atomicCompareExchange (destination : Addressing) (source : Reg)
deriving Repr, DecidableEq

structure DecodedInstruction where
  instruction : Instruction
  size : Nat
  trailing : Bytes
deriving Repr, DecidableEq

def registerOfCode : Nat -> Option Reg
  | 0 => some .eax
  | 1 => some .ecx
  | 2 => some .edx
  | 3 => some .ebx
  | 4 => some .esp
  | 5 => some .ebp
  | 6 => some .esi
  | 7 => some .edi
  | _ => none

def byteRegisterOfCode : Nat -> Option ByteRegister
  | 0 => some { parent := .eax, high := false }
  | 1 => some { parent := .ecx, high := false }
  | 2 => some { parent := .edx, high := false }
  | 3 => some { parent := .ebx, high := false }
  | 4 => some { parent := .eax, high := true }
  | 5 => some { parent := .ecx, high := true }
  | 6 => some { parent := .edx, high := true }
  | 7 => some { parent := .ebx, high := true }
  | _ => none

def readDisplacement (mode : Nat) (bytes : Bytes) : Option (Nat × Nat × Bytes) :=
  match mode, bytes with
  | 0, _ => some (0, 0, bytes)
  | 1, byte :: tail => some (signExtendImmediate8 byte, 1, tail)
  | 2, b0 :: b1 :: b2 :: b3 :: tail => do
      let value <- readImmediate32 [b0, b1, b2, b3]
      pure (value, 4, tail)
  | _, _ => none

structure ParsedModRM where
  reg : Reg
  operand : Operand32
  size : Nat
  trailing : Bytes
deriving Repr, DecidableEq

def parseModRM (bytes : Bytes) : Option ParsedModRM := do
  let modrm <- bytes.head?
  let tail := bytes.drop 1
  let mode := modrm / 64
  let regCode := (modrm / 8) % 8
  let rmCode := modrm % 8
  let reg <- registerOfCode regCode
  if mode == 3 then
    let rm <- registerOfCode rmCode
    pure { reg, operand := .register rm, size := 1, trailing := tail }
  else if rmCode == 4 then
    let sib <- tail.head?
    let afterSib := tail.drop 1
    let scaleShift := sib / 64
    let indexCode := (sib / 8) % 8
    let baseCode := sib % 8
    let index <- if indexCode == 4 then pure none else (registerOfCode indexCode).map some
    let absoluteBase := mode == 0 && baseCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode baseCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode afterSib
    pure {
      reg,
      operand := .memory { base, index, scaleShift, displacement },
      size := 2 + displacementSize,
      trailing,
    }
  else
    let absoluteBase := mode == 0 && rmCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode rmCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode tail
    pure {
      reg,
      operand := .memory { base, index := none, scaleShift := 0, displacement },
      size := 1 + displacementSize,
      trailing,
    }

structure ParsedModRM8 where
  reg : ByteRegister
  operand : Operand8
  size : Nat
  trailing : Bytes
deriving Repr, DecidableEq

def parseModRM8 (bytes : Bytes) : Option ParsedModRM8 := do
  let modrm <- bytes.head?
  let tail := bytes.drop 1
  let mode := modrm / 64
  let regCode := (modrm / 8) % 8
  let rmCode := modrm % 8
  let reg <- byteRegisterOfCode regCode
  if mode == 3 then
    let rm <- byteRegisterOfCode rmCode
    pure { reg, operand := .register rm, size := 1, trailing := tail }
  else if rmCode == 4 then
    let sib <- tail.head?
    let afterSib := tail.drop 1
    let scaleShift := sib / 64
    let indexCode := (sib / 8) % 8
    let baseCode := sib % 8
    let index <- if indexCode == 4 then pure none else (registerOfCode indexCode).map some
    let absoluteBase := mode == 0 && baseCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode baseCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode afterSib
    pure {
      reg,
      operand := .memory { base, index, scaleShift, displacement },
      size := 2 + displacementSize,
      trailing,
    }
  else
    let absoluteBase := mode == 0 && rmCode == 5
    let base <- if absoluteBase then pure none else (registerOfCode rmCode).map some
    let displacementMode := if absoluteBase then 2 else mode
    let (displacement, displacementSize, trailing) <- readDisplacement displacementMode tail
    pure {
      reg,
      operand := .memory { base, index := none, scaleShift := 0, displacement },
      size := 1 + displacementSize,
      trailing,
    }

def decodedModRM8 (instruction : ParsedModRM8 -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM8 bytes
  let instruction <- instruction parsed
  pure { instruction, size := 1 + parsed.size, trailing := parsed.trailing }

def decodedModRM8Immediate8 (instruction : ParsedModRM8 -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM8 bytes
  let immediate <- parsed.trailing.head?
  let instruction <- instruction parsed immediate
  pure { instruction, size := 2 + parsed.size, trailing := parsed.trailing.drop 1 }

def decodedModRM (instruction : ParsedModRM -> Option Instruction) (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let instruction <- instruction parsed
  pure { instruction, size := 1 + parsed.size, trailing := parsed.trailing }

def decodedModRMImmediate8 (instruction : ParsedModRM -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let immediate <- parsed.trailing.head?
  let instruction <- instruction parsed (signExtendImmediate8 immediate)
  pure { instruction, size := 2 + parsed.size, trailing := parsed.trailing.drop 1 }

def decodedModRMImmediate32 (instruction : ParsedModRM -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let value <- readU32 parsed.trailing 0
  let instruction <- instruction parsed value
  pure { instruction, size := 5 + parsed.size, trailing := parsed.trailing.drop 4 }

def decodedModRMImmediate16 (instruction : ParsedModRM -> Nat -> Option Instruction)
    (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let value <- readU16 parsed.trailing 0
  let instruction <- instruction parsed value
  pure { instruction, size := 3 + parsed.size, trailing := parsed.trailing.drop 2 }

def addInstructionPrefix (decoded : DecodedInstruction) : DecodedInstruction :=
  { decoded with size := decoded.size + 1 }

def decodeX87MemoryInstruction (opcode : Nat) (bytes : Bytes) : Option DecodedInstruction := do
  let parsed <- parseModRM bytes
  let address <-
    match parsed.operand with
    | .memory address => some address
    | .register _ | .immediate _ => none
  let instruction <-
    match opcode, parsed.reg with
    | 0xd9, .eax => some (.x87LoadMemory .float32 address)
    | 0xd9, .edx => some (.x87StoreMemory .float32 address false)
    | 0xd9, .ebx => some (.x87StoreMemory .float32 address true)
    | 0xd9, .ebp => some (.x87LoadControl address)
    | 0xd9, .edi => some (.x87StoreControl address)
    | 0xdd, .eax => some (.x87LoadMemory .float64 address)
    | 0xdd, .edx => some (.x87StoreMemory .float64 address false)
    | 0xdd, .ebx => some (.x87StoreMemory .float64 address true)
    | 0xdb, .eax => some (.x87LoadMemory .int32 address)
    | 0xdb, .edx => some (.x87StoreMemory .int32 address false)
    | 0xdb, .ebx => some (.x87StoreMemory .int32 address true)
    | 0xdb, .ebp => some (.x87LoadMemory .float80 address)
    | 0xdb, .edi => some (.x87StoreMemory .float80 address true)
    | 0xd8, .eax => some (.x87BinaryMemory .add .float32 address)
    | 0xd8, .ecx => some (.x87BinaryMemory .multiply .float32 address)
    | 0xd8, .esp => some (.x87BinaryMemory .subtract .float32 address)
    | 0xd8, .ebp => some (.x87BinaryMemory .reverseSubtract .float32 address)
    | 0xd8, .esi => some (.x87BinaryMemory .divide .float32 address)
    | 0xd8, .edi => some (.x87BinaryMemory .reverseDivide .float32 address)
    | 0xdc, .eax => some (.x87BinaryMemory .add .float64 address)
    | 0xdc, .ecx => some (.x87BinaryMemory .multiply .float64 address)
    | 0xdc, .esp => some (.x87BinaryMemory .subtract .float64 address)
    | 0xdc, .ebp => some (.x87BinaryMemory .reverseSubtract .float64 address)
    | 0xdc, .esi => some (.x87BinaryMemory .divide .float64 address)
    | 0xdc, .edi => some (.x87BinaryMemory .reverseDivide .float64 address)
    | _, _ => none
  pure { instruction, size := 1 + parsed.size, trailing := parsed.trailing }

def decodeX87RegisterInstruction : Bytes -> Option DecodedInstruction
  | opcode :: modrm :: tail =>
      let decoded (instruction : Instruction) := some { instruction, size := 2, trailing := tail }
      if opcode == 0xd9 && 0xc0 <= modrm && modrm <= 0xc7 then
        decoded (.x87LoadStack (modrm - 0xc0))
      else if opcode == 0xd9 && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87Exchange (modrm - 0xc8))
      else if opcode == 0xd9 && modrm == 0xe0 then
        decoded (.x87Unary .negate)
      else if opcode == 0xd9 && modrm == 0xe8 then
        decoded (.x87LoadConstant (0x3fff * (2 ^ 64) + (2 ^ 63)))
      else if opcode == 0xd9 && modrm == 0xee then
        decoded (.x87LoadConstant 0)
      else if opcode == 0xdd && 0xd0 <= modrm && modrm <= 0xd7 then
        decoded (.x87StoreStack (modrm - 0xd0) false)
      else if opcode == 0xdd && 0xd8 <= modrm && modrm <= 0xdf then
        decoded (.x87StoreStack (modrm - 0xd8) true)
      else if opcode == 0xd8 && 0xc0 <= modrm && modrm <= 0xc7 then
        decoded (.x87BinaryStack .add 0 (modrm - 0xc0) false)
      else if opcode == 0xd8 && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87BinaryStack .multiply 0 (modrm - 0xc8) false)
      else if opcode == 0xd8 && 0xf0 <= modrm && modrm <= 0xf7 then
        decoded (.x87BinaryStack .divide 0 (modrm - 0xf0) false)
      else if opcode == 0xdc && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87BinaryStack .multiply (modrm - 0xc8) 0 false)
      else if opcode == 0xde && 0xc0 <= modrm && modrm <= 0xc7 then
        decoded (.x87BinaryStack .add (modrm - 0xc0) 0 true)
      else if opcode == 0xde && 0xc8 <= modrm && modrm <= 0xcf then
        decoded (.x87BinaryStack .multiply (modrm - 0xc8) 0 true)
      else if opcode == 0xde && 0xe0 <= modrm && modrm <= 0xe7 then
        decoded (.x87BinaryStack .reverseSubtract (modrm - 0xe0) 0 true)
      else if opcode == 0xde && 0xe8 <= modrm && modrm <= 0xef then
        decoded (.x87BinaryStack .subtract (modrm - 0xe8) 0 true)
      else if opcode == 0xdb && 0xe8 <= modrm && modrm <= 0xf7 then
        decoded (.x87CompareStack (modrm % 8) false)
      else if opcode == 0xdf && 0xe8 <= modrm && modrm <= 0xf7 then
        decoded (.x87CompareStack (modrm % 8) true)
      else if opcode == 0xdb && modrm == 0xe3 then
        decoded .x87Initialize
      else if opcode == 0xdf && modrm == 0xe0 then
        decoded .x87StoreStatusAx
      else if opcode == 0xd9 && modrm == 0xe5 then
        decoded .x87Examine
      else
        decodeX87MemoryInstruction opcode (modrm :: tail)
  | _ => none

def decodeWordInstruction : Bytes -> Option DecodedInstruction
  | opcode :: tail =>
      if 0xb8 <= opcode && opcode <= 0xbf then do
        let destination <- registerOfCode (opcode - 0xb8)
        let value <- readU16 tail 0
        pure {
          instruction := .movImmediateWidth .word (.register destination) value
          size := 3
          trailing := tail.drop 2
        }
      else
        match opcode with
        | 0x8b => decodedModRM (fun parsed => some (.movFromOperandWidth .word parsed.reg parsed.operand)) tail
        | 0x89 => decodedModRM (fun parsed => some (.movToOperandWidth .word parsed.operand parsed.reg)) tail
        | 0xc7 => decodedModRMImmediate16 (fun parsed value =>
            if parsed.reg == .eax then some (.movImmediateWidth .word parsed.operand value) else none) tail
        | 0x3b => decodedModRM (fun parsed => some (.binaryWidth .word .compare (.register parsed.reg) parsed.operand)) tail
        | 0x2b => decodedModRM (fun parsed => some (.binaryWidth .word .sub (.register parsed.reg) parsed.operand)) tail
        | 0x39 => decodedModRM (fun parsed => some (.binaryWidth .word .compare parsed.operand (.register parsed.reg))) tail
        | 0x85 => decodedModRM (fun parsed => some (.binaryWidth .word .test parsed.operand (.register parsed.reg))) tail
        | 0xf7 => decodedModRMImmediate16 (fun parsed value =>
            if parsed.reg == .eax then some (.binaryWidth .word .test parsed.operand (.immediate value)) else none) tail
        | 0x83 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binaryWidth .word .add parsed.operand (.immediate value))
            | .ecx => some (.binaryWidth .word .or parsed.operand (.immediate value))
            | .esp => some (.binaryWidth .word .and parsed.operand (.immediate value))
            | .ebp => some (.binaryWidth .word .sub parsed.operand (.immediate value))
            | .esi => some (.binaryWidth .word .xor parsed.operand (.immediate value))
            | .edi => some (.binaryWidth .word .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0x81 => decodedModRMImmediate16 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binaryWidth .word .add parsed.operand (.immediate value))
            | .ecx => some (.binaryWidth .word .or parsed.operand (.immediate value))
            | .esp => some (.binaryWidth .word .and parsed.operand (.immediate value))
            | .ebp => some (.binaryWidth .word .sub parsed.operand (.immediate value))
            | .esi => some (.binaryWidth .word .xor parsed.operand (.immediate value))
            | .edi => some (.binaryWidth .word .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0x25 => do
            let value <- readU16 tail 0
            pure {
              instruction := .binaryWidth .word .and (.register .eax) (.immediate value)
              size := 3
              trailing := tail.drop 2
            }
        | 0x3d => do
            let value <- readU16 tail 0
            pure {
              instruction := .binaryWidth .word .compare (.register .eax) (.immediate value)
              size := 3
              trailing := tail.drop 2
            }
        | 0x2d => do
            let value <- readU16 tail 0
            pure {
              instruction := .binaryWidth .word .sub (.register .eax) (.immediate value)
              size := 3
              trailing := tail.drop 2
            }
        | _ => none
  | [] => none

def decodeGenericInstruction : Bytes -> Option DecodedInstruction
  | opcode :: tail =>
      if 0xb0 <= opcode && opcode <= 0xb7 then do
        let destination <- byteRegisterOfCode (opcode - 0xb0)
        let value <- tail.head?
        pure { instruction := .movImmediate8 (.register destination) value, size := 2, trailing := tail.drop 1 }
      else if 0xb8 <= opcode && opcode <= 0xbf then do
        let destination <- registerOfCode (opcode - 0xb8)
        let value <- readU32 tail 0
        pure { instruction := .movRegImm destination value, size := 5, trailing := tail.drop 4 }
      else if 0x50 <= opcode && opcode <= 0x57 then do
        let source <- registerOfCode (opcode - 0x50)
        pure { instruction := .pushReg source, size := 1, trailing := tail }
      else if 0x58 <= opcode && opcode <= 0x5f then do
        let destination <- registerOfCode (opcode - 0x58)
        pure { instruction := .popReg destination, size := 1, trailing := tail }
      else if 0x70 <= opcode && opcode <= 0x7f then do
        let displacement <- tail.head?
        let condition <- conditionOfCode (opcode - 0x70)
        pure { instruction := .branchCondition condition displacement 2, size := 2, trailing := tail.drop 1 }
      else
        match opcode with
        | 0xa1 => do
            let address <- readU32 tail 0
            pure {
              instruction := .movFromOperand .eax (.memory { base := none, index := none, scaleShift := 0, displacement := address }),
              size := 5,
              trailing := tail.drop 4,
            }
        | 0xa3 => do
            let address <- readU32 tail 0
            pure {
              instruction := .movToOperand (.memory { base := none, index := none, scaleShift := 0, displacement := address }) .eax,
              size := 5,
              trailing := tail.drop 4,
            }
        | 0x8b => decodedModRM (fun parsed => some (.movFromOperand parsed.reg parsed.operand)) tail
        | 0x89 => decodedModRM (fun parsed => some (.movToOperand parsed.operand parsed.reg)) tail
        | 0x8a => decodedModRM8 (fun parsed => some (.movFromOperand8 parsed.reg parsed.operand)) tail
        | 0x88 => decodedModRM8 (fun parsed => some (.movToOperand8 parsed.operand parsed.reg)) tail
        | 0xc6 => decodedModRM8Immediate8 (fun parsed value =>
            if parsed.reg == { parent := .eax, high := false } then some (.movImmediate8 parsed.operand value) else none) tail
        | 0x8d => decodedModRM (fun parsed =>
            match parsed.operand with
            | .memory address => some (.leaAddress parsed.reg address)
            | .register _ | .immediate _ => none) tail
        | 0x87 => decodedModRM (fun parsed => some (.exchange parsed.operand parsed.reg)) tail
        | 0x69 => decodedModRMImmediate32 (fun parsed value =>
            some (.multiplyLow parsed.reg parsed.operand (some value))) tail
        | 0x6b => decodedModRMImmediate8 (fun parsed value =>
            some (.multiplyLow parsed.reg parsed.operand (some value))) tail
        | 0x98 => some { instruction := .convertWordToDword, size := 1, trailing := tail }
        | 0x99 => some { instruction := .convertDwordToQuad, size := 1, trailing := tail }
        | 0xc7 => decodedModRMImmediate32 (fun parsed value =>
            if parsed.reg == .eax then some (.movImmediate parsed.operand value) else none) tail
        | 0x03 => decodedModRM (fun parsed => some (.binary .add (.register parsed.reg) parsed.operand)) tail
        | 0x01 => decodedModRM (fun parsed => some (.binary .add parsed.operand (.register parsed.reg))) tail
        | 0x13 => decodedModRM (fun parsed => some (.binaryCarry false (.register parsed.reg) parsed.operand)) tail
        | 0x11 => decodedModRM (fun parsed => some (.binaryCarry false parsed.operand (.register parsed.reg))) tail
        | 0x1b => decodedModRM (fun parsed => some (.binaryCarry true (.register parsed.reg) parsed.operand)) tail
        | 0x19 => decodedModRM (fun parsed => some (.binaryCarry true parsed.operand (.register parsed.reg))) tail
        | 0x2b => decodedModRM (fun parsed => some (.binary .sub (.register parsed.reg) parsed.operand)) tail
        | 0x29 => decodedModRM (fun parsed => some (.binary .sub parsed.operand (.register parsed.reg))) tail
        | 0x33 => decodedModRM (fun parsed => some (.binary .xor (.register parsed.reg) parsed.operand)) tail
        | 0x31 => decodedModRM (fun parsed => some (.binary .xor parsed.operand (.register parsed.reg))) tail
        | 0x23 => decodedModRM (fun parsed => some (.binary .and (.register parsed.reg) parsed.operand)) tail
        | 0x21 => decodedModRM (fun parsed => some (.binary .and parsed.operand (.register parsed.reg))) tail
        | 0x0b => decodedModRM (fun parsed => some (.binary .or (.register parsed.reg) parsed.operand)) tail
        | 0x09 => decodedModRM (fun parsed => some (.binary .or parsed.operand (.register parsed.reg))) tail
        | 0x3b => decodedModRM (fun parsed => some (.binary .compare (.register parsed.reg) parsed.operand)) tail
        | 0x39 => decodedModRM (fun parsed => some (.binary .compare parsed.operand (.register parsed.reg))) tail
        | 0x85 => decodedModRM (fun parsed => some (.binary .test parsed.operand (.register parsed.reg))) tail
        | 0x84 => decodedModRM8 (fun parsed => some (.binary8 .test parsed.operand (.register parsed.reg))) tail
        | 0x3a => decodedModRM8 (fun parsed => some (.binary8 .compare (.register parsed.reg) parsed.operand)) tail
        | 0x38 => decodedModRM8 (fun parsed => some (.binary8 .compare parsed.operand (.register parsed.reg))) tail
        | 0x0a => decodedModRM8 (fun parsed => some (.binary8 .or (.register parsed.reg) parsed.operand)) tail
        | 0x22 => decodedModRM8 (fun parsed => some (.binary8 .and (.register parsed.reg) parsed.operand)) tail
        | 0x80 => decodedModRM8Immediate8 (fun parsed value =>
            match parsed.reg with
            | { parent := .eax, high := false } => some (.binary8 .add parsed.operand (.immediate value))
            | { parent := .ecx, high := false } => some (.binary8 .or parsed.operand (.immediate value))
            | { parent := .eax, high := true } => some (.binary8 .and parsed.operand (.immediate value))
            | { parent := .ecx, high := true } => some (.binary8 .sub parsed.operand (.immediate value))
            | { parent := .edx, high := true } => some (.binary8 .xor parsed.operand (.immediate value))
            | { parent := .ebx, high := true } => some (.binary8 .compare parsed.operand (.immediate value))
            | _ => none) tail
        | 0x83 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binary .add parsed.operand (.immediate value))
            | .ecx => some (.binary .or parsed.operand (.immediate value))
            | .edx => some (.binaryCarry false parsed.operand (.immediate value))
            | .ebx => some (.binaryCarry true parsed.operand (.immediate value))
            | .esp => some (.binary .and parsed.operand (.immediate value))
            | .ebp => some (.binary .sub parsed.operand (.immediate value))
            | .esi => some (.binary .xor parsed.operand (.immediate value))
            | .edi => some (.binary .compare parsed.operand (.immediate value))) tail
        | 0x81 => decodedModRMImmediate32 (fun parsed value =>
            match parsed.reg with
            | .eax => some (.binary .add parsed.operand (.immediate value))
            | .ecx => some (.binary .or parsed.operand (.immediate value))
            | .edx => some (.binaryCarry false parsed.operand (.immediate value))
            | .ebx => some (.binaryCarry true parsed.operand (.immediate value))
            | .esp => some (.binary .and parsed.operand (.immediate value))
            | .ebp => some (.binary .sub parsed.operand (.immediate value))
            | .esi => some (.binary .xor parsed.operand (.immediate value))
            | .edi => some (.binary .compare parsed.operand (.immediate value))) tail
        | 0x05 => do
            let value <- readU32 tail 0
            pure { instruction := .binary .add (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x0d => do
            let value <- readU32 tail 0
            pure { instruction := .binary .or (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x25 => do
            let value <- readU32 tail 0
            pure { instruction := .binary .and (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x2d => do
            let value <- readU32 tail 0
            pure { instruction := .binary .sub (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0x35 => do
            let value <- readU32 tail 0
            pure { instruction := .binary .xor (.register .eax) (.immediate value), size := 5, trailing := tail.drop 4 }
        | 0xc1 => decodedModRMImmediate8 (fun parsed value =>
            match parsed.reg with
            | .esp => some (.shift .left parsed.operand (.immediate (value % 32)))
            | .ebp => some (.shift .right parsed.operand (.immediate (value % 32)))
            | .edi => some (.shift .arithmeticRight parsed.operand (.immediate (value % 32)))
            | _ => none) tail
        | 0xd1 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .esp => some (.shift .left parsed.operand (.immediate 1))
            | .ebp => some (.shift .right parsed.operand (.immediate 1))
            | .edi => some (.shift .arithmeticRight parsed.operand (.immediate 1))
            | _ => none) tail
        | 0xd3 => decodedModRM (fun parsed =>
            match parsed.reg with
            | .esp => some (.shift .left parsed.operand .cl)
            | .ebp => some (.shift .right parsed.operand .cl)
            | .edi => some (.shift .arithmeticRight parsed.operand .cl)
            | _ => none) tail
        | 0xf6 => decodedModRM8Immediate8 (fun parsed value =>
            if parsed.reg == { parent := .eax, high := false } then
              some (.binary8 .test parsed.operand (.immediate value))
            else none) tail
        | 0xf7 => do
            let parsed <- parseModRM tail
            match parsed.reg with
            | .eax => do
                let value <- readU32 parsed.trailing 0
                pure {
                  instruction := .binary .test parsed.operand (.immediate value)
                  size := 5 + parsed.size
                  trailing := parsed.trailing.drop 4
                }
            | .edx => pure { instruction := .unary .bitNot parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .ebx => pure { instruction := .unary .negate parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .esp => pure { instruction := .multiplyFull false parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .ebp => pure { instruction := .multiplyFull true parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | .esi => pure { instruction := .divideUnsigned parsed.operand, size := 1 + parsed.size, trailing := parsed.trailing }
            | _ => none
        | 0xff => decodedModRM (fun parsed =>
            match parsed.reg with
            | .edx => some (.callIndirect parsed.operand)
            | .esp => some (.jumpIndirect parsed.operand)
            | .esi => some (.pushOperand parsed.operand)
            | _ => none) tail
        | 0xa8 =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .test (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0xa9 => do
            let value <- readU32 tail 0
            pure {
              instruction := .binary .test (.register .eax) (.immediate value)
              size := 5
              trailing := tail.drop 4
            }
        | 0x3c =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .compare (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x24 =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .and (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x0c =>
            match tail with
            | value :: trailing => some {
                instruction := .binary8 .or (.register { parent := .eax, high := false }) (.immediate value)
                size := 2
                trailing
              }
            | _ => none
        | 0x72 =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .below displacement 2, size := 2, trailing }
            | _ => none
        | 0x77 =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .above displacement 2, size := 2, trailing }
            | _ => none
        | 0x7f =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .greater displacement 2, size := 2, trailing }
            | _ => none
        | 0x73 =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .aboveOrEqual displacement 2, size := 2, trailing }
            | _ => none
        | 0x7e =>
            match tail with
            | displacement :: trailing => some { instruction := .branchCondition .lessOrEqual displacement 2, size := 2, trailing }
            | _ => none
        | _ => none
  | [] => none

def decodeInstruction : Bytes -> Option DecodedInstruction
  | 0x90 :: tail => some { instruction := .nop, size := 1, trailing := tail }
  | 0x9b :: tail => some { instruction := .nop, size := 1, trailing := tail }
  | 0xf3 :: 0xa5 :: tail => some { instruction := .moveDwords true, size := 2, trailing := tail }
  | 0xa5 :: tail => some { instruction := .moveDwords false, size := 1, trailing := tail }
  | 0x64 :: 0x8b :: tail => do
      let parsed <- parseModRM tail
      let source <-
        match parsed.operand with
        | .memory source => some source
        | .register _ | .immediate _ => none
      pure {
        instruction := .movFs32 parsed.reg source
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0xf0 :: 0x0f :: 0xb1 :: tail => do
      let parsed <- parseModRM tail
      let destination <-
        match parsed.operand with
        | .memory destination => some destination
        | .register _ | .immediate _ => none
      pure {
        instruction := .atomicCompareExchange destination parsed.reg
        size := 3 + parsed.size
        trailing := parsed.trailing
      }
  | 0x66 :: 0x90 :: tail => some { instruction := .nop, size := 2, trailing := tail }
  | 0x66 :: bytes => (decodeWordInstruction bytes).map addInstructionPrefix
  | 0x2e :: 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => some { instruction := .nop, size := 5, trailing := tail }
  | 0x2e :: 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 8, trailing := tail }
  | 0x8d :: 0xb6 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 6, trailing := tail }
  | 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail =>
      some { instruction := .nop, size := 7, trailing := tail }
  | 0xc3 :: tail => some { instruction := .ret, size := 1, trailing := tail }
  | 0xc9 :: tail => some { instruction := .leave, size := 1, trailing := tail }
  | 0xc2 :: b0 :: b1 :: tail => do
      let bytes <- readU16 [b0, b1] 0
      pure { instruction := .retPop bytes, size := 3, trailing := tail }
  | 0xb8 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let value <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .movRegImm .eax value, size := 5, trailing := tail }
  | 0x89 :: 0xd8 :: tail => some { instruction := .movRegReg .eax .ebx, size := 2, trailing := tail }
  | 0x8d :: 0x03 :: tail => some { instruction := .lea .eax .ebx 0, size := 2, trailing := tail }
  | 0x89 :: 0xda :: tail => some { instruction := .movRegReg .edx .ebx, size := 2, trailing := tail }
  | 0x8d :: 0x13 :: tail => some { instruction := .lea .edx .ebx 0, size := 2, trailing := tail }
  | 0x83 :: 0xc0 :: 0x00 :: tail => some { instruction := .addZero .eax, size := 3, trailing := tail }
  | 0x83 :: 0xe8 :: 0x00 :: tail => some { instruction := .subZero .eax, size := 3, trailing := tail }
  | 0x83 :: 0xf8 :: immediate :: tail =>
      some { instruction := .cmpImm .eax (signExtendImmediate8 immediate), size := 3, trailing := tail }
  | 0x3d :: b0 :: b1 :: b2 :: b3 :: tail => do
      let value <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .cmpImm .eax value, size := 5, trailing := tail }
  | 0x74 :: displacement :: tail => some { instruction := .branchEqual false displacement, size := 2, trailing := tail }
  | 0x75 :: displacement :: tail => some { instruction := .branchEqual true displacement, size := 2, trailing := tail }
  | 0xeb :: displacement :: tail => some { instruction := .jumpRel8 displacement, size := 2, trailing := tail }
  | 0xe9 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let displacement <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .jumpRel32 displacement, size := 5, trailing := tail }
  | 0xe8 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let displacement <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .callRel32 displacement, size := 5, trailing := tail }
  | 0xff :: 0x15 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let address <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .callImport address, size := 6, trailing := tail }
  | 0xff :: 0x25 :: b0 :: b1 :: b2 :: b3 :: tail => do
      let address <- readImmediate32 [b0, b1, b2, b3]
      pure { instruction := .jumpImport address, size := 6, trailing := tail }
  | 0x50 :: tail => some { instruction := .pushReg .eax, size := 1, trailing := tail }
  | 0xff :: 0xf0 :: tail => some { instruction := .pushReg .eax, size := 2, trailing := tail }
  | 0x5b :: tail => some { instruction := .popReg .ebx, size := 1, trailing := tail }
  | 0x8f :: 0xc3 :: tail => some { instruction := .popReg .ebx, size := 2, trailing := tail }
  | 0x8d :: 0x57 :: 0x04 :: tail => some { instruction := .lea .edx .edi 4, size := 3, trailing := tail }
  | 0x8b :: 0x06 :: tail => some { instruction := .load32 .eax .esi 0, size := 2, trailing := tail }
  | 0x8b :: 0x46 :: 0x00 :: tail => some { instruction := .load32 .eax .esi 0, size := 3, trailing := tail }
  | 0x8b :: 0x03 :: tail => some { instruction := .load32 .eax .ebx 0, size := 2, trailing := tail }
  | 0x8b :: 0x43 :: 0x00 :: tail => some { instruction := .load32 .eax .ebx 0, size := 3, trailing := tail }
  | 0x8b :: 0x0b :: tail => some { instruction := .load32 .ecx .ebx 0, size := 2, trailing := tail }
  | 0x8b :: 0x4b :: 0x00 :: tail => some { instruction := .load32 .ecx .ebx 0, size := 3, trailing := tail }
  | 0x89 :: 0x02 :: tail => some { instruction := .store32 .edx 0 .eax, size := 2, trailing := tail }
  | 0x89 :: 0x47 :: 0x04 :: tail => some { instruction := .store32 .edi 4 .eax, size := 3, trailing := tail }
  | 0x89 :: 0x03 :: tail => some { instruction := .store32 .ebx 0 .eax, size := 2, trailing := tail }
  | 0x89 :: 0x43 :: 0x00 :: tail => some { instruction := .store32 .ebx 0 .eax, size := 3, trailing := tail }
  | 0x29 :: 0xc0 :: tail => some { instruction := .zeroReg .eax, size := 2, trailing := tail }
  | 0x31 :: 0xc0 :: tail => some { instruction := .zeroReg .eax, size := 2, trailing := tail }
  | 0x0f :: 0xb7 :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movZeroExtend parsed.reg parsed.operand 16,
        size := 2 + parsed.size,
        trailing := parsed.trailing,
      }
  | 0x0f :: 0xb6 :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movZeroExtend parsed.reg parsed.operand 8,
        size := 2 + parsed.size,
        trailing := parsed.trailing,
      }
  | 0x0f :: 0xbf :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movSignExtend parsed.reg parsed.operand 16
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xbe :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .movSignExtend parsed.reg parsed.operand 8
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xaf :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .multiplyLow parsed.reg parsed.operand none
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: 0xbd :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .bitScan true parsed.reg parsed.operand
        size := 2 + parsed.size
        trailing := parsed.trailing
      }
  | 0xf3 :: 0x0f :: 0xbc :: tail => do
      let parsed <- parseModRM tail
      pure {
        instruction := .bitScan false parsed.reg parsed.operand
        size := 3 + parsed.size
        trailing := parsed.trailing
      }
  | 0x0f :: opcode :: tail =>
      if opcode == 0xa4 || opcode == 0xac then do
        let parsed <- parseModRM tail
        let immediate <- parsed.trailing.head?
        pure {
          instruction := .doubleShift (opcode == 0xa4) parsed.operand parsed.reg (.immediate (immediate % 32))
          size := 3 + parsed.size
          trailing := parsed.trailing.drop 1
        }
      else if opcode == 0xa5 || opcode == 0xad then do
        let parsed <- parseModRM tail
        pure {
          instruction := .doubleShift (opcode == 0xa5) parsed.operand parsed.reg .cl
          size := 2 + parsed.size
          trailing := parsed.trailing
        }
      else if 0x40 <= opcode && opcode <= 0x4f then do
        let condition <- conditionOfCode (opcode - 0x40)
        let parsed <- parseModRM tail
        pure {
          instruction := .conditionalMove condition parsed.reg parsed.operand
          size := 2 + parsed.size
          trailing := parsed.trailing
        }
      else if 0x90 <= opcode && opcode <= 0x9f then do
        let condition <- conditionOfCode (opcode - 0x90)
        let parsed <- parseModRM8 tail
        pure {
          instruction := .setCondition condition parsed.operand
          size := 2 + parsed.size
          trailing := parsed.trailing
        }
      else if 0x80 <= opcode && opcode <= 0x8f then do
        let condition <- conditionOfCode (opcode - 0x80)
        let displacement <- readU32 tail 0
        pure {
          instruction := .branchCondition condition displacement 6
          size := 6
          trailing := tail.drop 4
        }
      else
        none
  | bytes =>
      match decodeX87RegisterInstruction bytes with
      | some decoded => some decoded
      | none => decodeGenericInstruction bytes

def importAtAbsoluteAddress (pe : PE32) (absoluteAddress : Nat) : Option PEImport := do
  if absoluteAddress < pe.imageBase then none else
  let imports <- parseImports pe
  imports.find? (fun imported => imported.iatRva == absoluteAddress - pe.imageBase)

def importAtAbsoluteAddressFrom (imageBase : Nat) (imports : List PEImport)
    (absoluteAddress : Nat) : Option PEImport := do
  if absoluteAddress < imageBase then none else
  imports.find? (fun imported => imported.iatRva == absoluteAddress - imageBase)

def zeroArgumentImport (imported : PEImport) : Bool :=
  match imported.name with
  | .ordinal _ => false
  | .symbol bytes =>
      (imported.dll == [0x4b, 0x45, 0x52, 0x4e, 0x45, 0x4c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c] &&
        bytes == [0x47, 0x65, 0x74, 0x54, 0x69, 0x63, 0x6b, 0x43, 0x6f, 0x75, 0x6e, 0x74]) ||
      bytes.reverse.take 2 == [0x30, 0x40]

def Addressing.expression (addressing : Addressing) (registers : Registers Expr) : Expr :=
  let base := addressing.base.map (Registers.get registers) |>.getD (.constant 0)
  let index := addressing.index.map (Registers.get registers) |>.getD (.constant 0)
  let index := if addressing.scaleShift == 0 then index else .shiftLeft index addressing.scaleShift
  Expr.addNormalized (Expr.addNormalized base index) (.constant addressing.displacement)

def readOperand32 (state : SymbolicBehavior) : Operand32 -> Expr
  | .register reg => state.registers.get reg
  | .memory addressing => symbolicRead32 state (addressing.expression state.registers)
  | .immediate value => .constant value

def writeOperand32 (state : SymbolicBehavior) (destination : Operand32) (value : Expr) : Option SymbolicBehavior :=
  match destination with
  | .register reg => some { state with registers := state.registers.set reg value }
  | .memory addressing => some (state.write32 (addressing.expression state.registers) value)
  | .immediate _ => none

def readOperandWidth (width : OperandWidth) (state : SymbolicBehavior) : Operand32 -> Expr
  | .register reg => .bitAnd (state.registers.get reg) (.constant (2 ^ width.bits - 1))
  | .memory addressing =>
      let address := addressing.expression state.registers
      match width with
      | .byte => symbolicRead8 state address
      | .word => symbolicRead16 state address
  | .immediate value => .constant (value % (2 ^ width.bits))

def writeOperandWidth (width : OperandWidth) (state : SymbolicBehavior)
    (destination : Operand32) (value : Expr) : Option SymbolicBehavior :=
  let mask := 2 ^ width.bits - 1
  let value := Expr.bitAnd value (.constant mask)
  match destination with
  | .register reg =>
      let preserved := .bitAnd (state.registers.get reg) (.constant (2 ^ 32 - 1 - mask))
      some { state with registers := state.registers.set reg (.bitOr preserved value) }
  | .memory addressing =>
      let address := addressing.expression state.registers
      let composed :=
        match width with
        | .byte =>
            .bitOr value
              (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 1)) 8)
                (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 2)) 16)
                  (.shiftLeft (symbolicRead8 state (address.offset 3)) 24)))
        | .word =>
            .bitOr value
              (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 2)) 16)
                (.shiftLeft (symbolicRead8 state (address.offset 3)) 24))
      some (state.write32 address composed)
  | .immediate _ => none

def readByteRegister (state : SymbolicBehavior) (register : ByteRegister) : Expr :=
  let value := state.registers.get register.parent
  if register.high then
    .bitAnd (.shiftRight value 8) (.constant 0xff)
  else
    .bitAnd value (.constant 0xff)

def writeByteRegister (state : SymbolicBehavior) (register : ByteRegister) (value : Expr) : SymbolicBehavior :=
  let current := state.registers.get register.parent
  let value := .bitAnd value (.constant 0xff)
  let result :=
    if register.high then
      .bitOr (.bitAnd current (.constant 0xffff00ff)) (.shiftLeft value 8)
    else
      .bitOr (.bitAnd current (.constant 0xffffff00)) value
  { state with registers := state.registers.set register.parent result }

def readOperand8 (state : SymbolicBehavior) : Operand8 -> Expr
  | .register reg => readByteRegister state reg
  | .memory addressing => symbolicRead8 state (addressing.expression state.registers)
  | .immediate value => .constant (value % 256)

def writeOperand8 (state : SymbolicBehavior) (destination : Operand8) (value : Expr) : Option SymbolicBehavior :=
  let value := Expr.bitAnd value (.constant 0xff)
  match destination with
  | .register reg => some (writeByteRegister state reg value)
  | .memory addressing =>
      let address := addressing.expression state.registers
      let composed :=
        .bitOr value
          (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 1)) 8)
            (.bitOr (.shiftLeft (symbolicRead8 state (address.offset 2)) 16)
              (.shiftLeft (symbolicRead8 state (address.offset 3)) 24)))
      some (state.write32 address composed)
  | .immediate _ => none

def conditionExpression (flags : FlagsExpr) : Condition -> Option BoolExpr
  | .overflow => flags.overflow
  | .notOverflow => flags.overflow.map BoolExpr.not
  | .equal => flags.zero
  | .notEqual => flags.zero.map BoolExpr.not
  | .below => flags.carry
  | .aboveOrEqual => flags.carry.map BoolExpr.not
  | .belowOrEqual => do
      let carry <- flags.carry
      let zero <- flags.zero
      pure (.or carry zero)
  | .above => do
      let carry <- flags.carry
      let zero <- flags.zero
      pure (.and (.not carry) (.not zero))
  | .sign => flags.sign
  | .notSign => flags.sign.map BoolExpr.not
  | .parity => flags.parity
  | .notParity => flags.parity.map BoolExpr.not
  | .less => do
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.xor sign overflow)
  | .greaterOrEqual => do
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.not (.xor sign overflow))
  | .greater => do
      let zero <- flags.zero
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.and (.not zero) (.not (.xor sign overflow)))
  | .lessOrEqual => do
      let zero <- flags.zero
      let sign <- flags.sign
      let overflow <- flags.overflow
      pure (.or zero (.xor sign overflow))

def DecodedInstruction.consumesExactly
    (decoded : DecodedInstruction) (input : Bytes) : Bool :=
  decoded.size > 0 && decoded.size <= 15 && decoded.size <= input.length &&
    decoded.trailing == input.drop decoded.size

/-- Fail closed unless the decoder's size and trailing bytes form an exact,
nonempty IA-32 instruction prefix of the fetched bytes. -/
def decodeInstructionExact (input : Bytes) : Option DecodedInstruction := do
  let decoded <- decodeInstruction input
  if decoded.consumesExactly input then some decoded else none

inductive InstructionResult where
  | next (state : SymbolicBehavior)
  | stop (state : SymbolicBehavior)

def lowestSetBitExpression (value : Expr) : Nat -> Nat -> Expr
  | _, 0 => .constant 32
  | index, fuel + 1 =>
      .ifEqual (.bitValue value index) (.constant 1) (.constant index)
        (lowestSetBitExpression value (index + 1) fuel)

def highestSetBitExpression (value : Expr) : Nat -> Nat -> Expr
  | _, 0 => .constant 0
  | index, fuel + 1 =>
      .ifEqual (.bitValue value index) (.constant 1) (.constant index)
        (highestSetBitExpression value (index - 1) fuel)

theorem eval_lowestSetBitExpression (state : MachineState) (value : Expr) (index fuel : Nat) :
    (lowestSetBitExpression value index fuel).eval state =
      lowestSetBitValue (value.eval state) index fuel := by
  induction fuel generalizing index with
  | zero => rfl
  | succ fuel inductionHypothesis =>
      simp only [lowestSetBitExpression, Expr.eval, lowestSetBitValue]
      split
      · rfl
      · exact inductionHypothesis (index + 1)

theorem eval_highestSetBitExpression (state : MachineState) (value : Expr) (index fuel : Nat) :
    (highestSetBitExpression value index fuel).eval state =
      highestSetBitValue (value.eval state) index fuel := by
  induction fuel generalizing index with
  | zero => rfl
  | succ fuel inductionHypothesis =>
      simp only [highestSetBitExpression, Expr.eval, highestSetBitValue]
      split
      · rfl
      · exact inductionHypothesis (index - 1)

theorem eval_lowestSetBit_compact (state : MachineState) (value : Expr) :
    (Expr.lowestSetBit value).eval state =
      (lowestSetBitExpression value 0 32).eval state := by
  rw [eval_lowestSetBitExpression]
  rfl

theorem eval_highestSetBit_compact (state : MachineState) (value : Expr) :
    (Expr.highestSetBit value).eval state =
      (highestSetBitExpression value 31 32).eval state := by
  rw [eval_highestSetBitExpression]
  rfl

def x87LoadExpression (pe : PE32) (format : X87LoadFormat)
    (address control : Expr) : X87Expr :=
  match address with
  | .constant absolute =>
      match readImmutableImageWord pe absolute format.byteWidth with
      | some raw => .imageLoad format raw control
      | none => .load format address control
  | _ => .load format address control

def executeInstruction (pe : PE32) (imports : List PEImport)
    (pc undefinedSlot : Nat) (decoded : DecodedInstruction)
    (state : SymbolicBehavior) : Option InstructionResult :=
  let nextRva := pc + decoded.size
  match decoded.instruction with
  | .nop => some (.next state)
  | .ret =>
      let stack := state.registers.esp
      let target := symbolicRead32 state stack
      some (.stop {
        state with
        registers := state.registers.set .esp (stack.offset 4)
        outcome := some (.returned target)
      })
  | .retPop bytes =>
      let stack := state.registers.esp
      let target := symbolicRead32 state stack
      some (.stop {
        state with
        registers := state.registers.set .esp (stack.offset (4 + bytes))
        outcome := some (.returned target)
      })
  | .movRegImm destination value =>
      some (.next { state with registers := state.registers.set destination (.constant value) })
  | .movRegReg destination source =>
      some (.next { state with registers := state.registers.set destination (state.registers.get source) })
  | .addZero destination =>
      let value := state.registers.get destination
      some (.next {
        state with
        comparison := some (value, .constant 0)
        flags := some (additionFlags value (.constant 0) value)
      })
  | .subZero destination =>
      let value := state.registers.get destination
      some (.next {
        state with
        comparison := some (value, .constant 0)
        flags := some (subtractionFlags value (.constant 0) value)
      })
  | .cmpImm source value =>
      let left := state.registers.get source
      let right := .constant value
      let result := Expr.subNormalized left right
      some (.next {
        state with
        comparison := some (left, right)
        flags := some (subtractionFlags left right result)
      })
  | .branchEqual inverted displacement => do
      let condition <-
        match state.flags with
        | some flags => flags.zero
        | none => state.comparison.map (fun comparison => .equal comparison.1 comparison.2)
      let condition := if inverted then .not condition else condition
      some (.stop { state with outcome := some (.branch condition (relativeTarget8 nextRva displacement) nextRva) })
  | .jumpRel8 displacement =>
      some (.stop { state with outcome := some (.jump (relativeTarget8 nextRva displacement)) })
  | .jumpRel32 displacement =>
      some (.stop { state with outcome := some (.jump (relativeTarget32 nextRva displacement)) })
  | .pushReg source =>
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack (state.registers.get source)
      some (.next { state with registers := state.registers.set .esp stack })
  | .pushOperand source =>
      let value := readOperand32 state source
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack value
      some (.next { state with registers := state.registers.set .esp stack })
  | .movFs32 destination source =>
      let address := Expr.addNormalized (.inputFsBase) (source.expression state.registers)
      some (.next { state with registers := state.registers.set destination (symbolicRead32 state address) })
  | .popReg destination =>
      let value := symbolicRead32 state state.registers.esp
      let stack := state.registers.esp.offset 4
      some (.next { state with registers := (state.registers.set destination value).set .esp stack })
  | .leave =>
      let stack := state.registers.ebp
      let value := symbolicRead32 state stack
      some (.next {
        state with
        registers := (state.registers.set .ebp value).set .esp (stack.offset 4)
      })
  | .lea destination base offset =>
      some (.next { state with registers := state.registers.set destination ((state.registers.get base).offset offset) })
  | .load32 destination base offset =>
      let value := symbolicRead32 state ((state.registers.get base).offset offset)
      some (.next { state with registers := state.registers.set destination value })
  | .store32 base offset source =>
      some (.next (state.write32 ((state.registers.get base).offset offset) (state.registers.get source)))
  | .zeroReg destination =>
      some (.next {
        state with
        registers := state.registers.set destination (.constant 0)
        comparison := some (.constant 0, .constant 0)
        flags := some (logicalFlags undefinedSlot (.constant 0))
      })
  | .callRel32 displacement =>
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack (.constant (pe.imageBase + nextRva))
      some (.stop {
        state with
        registers := state.registers.set .esp stack
        outcome := some (.call (relativeTarget32 nextRva displacement) nextRva (pe.imageBase + nextRva))
      })
  | .callImport absoluteAddress =>
      match importAtAbsoluteAddressFrom pe.imageBase imports absoluteAddress with
      | some imported => some (.stop { state with outcome := some (.externalCall imported [] nextRva) })
      | none =>
          let target := symbolicRead32 state (.constant absoluteAddress)
          let stack := state.registers.esp.offset (2 ^ 32 - 4)
          let state := state.write32 stack (.constant (pe.imageBase + nextRva))
          some (.stop {
            state with
            registers := state.registers.set .esp stack
            outcome := some (.indirectCall target nextRva (pe.imageBase + nextRva))
          })
  | .jumpImport absoluteAddress =>
      match importAtAbsoluteAddressFrom pe.imageBase imports absoluteAddress with
      | some imported => some (.stop { state with outcome := some (.externalJump imported []) })
      | none => some (.stop {
          state with outcome := some (.indirectJump (symbolicRead32 state (.constant absoluteAddress)))
        })
  | .movFromOperand destination source =>
      some (.next { state with registers := state.registers.set destination (readOperand32 state source) })
  | .movToOperand destination source => do
      let next <- writeOperand32 state destination (state.registers.get source)
      some (.next next)
  | .movImmediate destination value => do
      let next <- writeOperand32 state destination (.constant value)
      some (.next next)
  | .leaAddress destination source =>
      some (.next { state with registers := state.registers.set destination (source.expression state.registers) })
  | .binary operation destination source => do
      let left := readOperand32 state destination
      let right := readOperand32 state source
      let result :=
        match operation with
        | .add => Expr.addNormalized left right
        | .sub | .compare => Expr.subNormalized left right
        | .xor => Expr.xorNormalized left right
        | .and | .test => .bitAnd left right
        | .or => .bitOr left right
      let flags :=
        match operation with
        | .add => additionFlags left right result
        | .sub | .compare => subtractionFlags left right result
        | .xor | .and | .or | .test => logicalFlags undefinedSlot result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperand32 state destination result
      some (.next { next with flags := some flags })
  | .shift operation destination count => do
      let value := readOperand32 state destination
      let amount :=
        match count with
        | .immediate amount => Expr.constant amount
        | .cl => .bitAnd (state.registers.get .ecx) (.constant 0x1f)
      let result :=
        match operation, count with
        | .left, .immediate amount => .shiftLeft value amount
        | .right, .immediate amount => .shiftRight value amount
        | .arithmeticRight, .immediate amount => .shiftArithmeticRightBy value (.constant amount)
        | .left, .cl => .shiftLeftBy value amount
        | .right, .cl => .shiftRightBy value amount
        | .arithmeticRight, .cl => .shiftArithmeticRightBy value amount
      let next <- writeOperand32 state destination result
      let flags :=
        match count with
        | .cl => none
        | .immediate rawAmount =>
            let shiftAmount := rawAmount % 32
            if shiftAmount == 0 then state.flags else
            let carryIndex :=
              match operation with
              | .left => 32 - shiftAmount
              | .right | .arithmeticRight => shiftAmount - 1
            let carry := BoolExpr.bit value carryIndex
            let overflow :=
              if shiftAmount != 1 then none else
              match operation with
              | .left => some (.xor (.msb value) carry)
              | .right => some (.msb value)
              | .arithmeticRight => some (.equal (.constant 0) (.constant 1))
            some {
              zero := some (.equal result (.constant 0))
              carry := some carry
              auxiliary := some (.bit (.undefined undefinedSlot) 0)
              sign := some (.msb result)
              overflow
              parity := some (parityExpression result)
            }
      some (.next { next with flags, comparison := none })
  | .unary operation destination => do
      let value := readOperand32 state destination
      let result :=
        match operation with
        | .bitNot => .bitNot value
        | .negate => Expr.subNormalized (.constant 0) value
      let next <- writeOperand32 state destination result
      let flags :=
        match operation with
        | .bitNot => state.flags
        | .negate => some (subtractionFlags (.constant 0) value result)
      some (.next { next with flags })
  | .branchCondition condition displacement size => do
      let flags <- state.flags
      let condition <- conditionExpression flags condition
      let target := if size == 2 then relativeTarget8 nextRva displacement else relativeTarget32 nextRva displacement
      some (.stop {
        state with outcome := some (.branch condition target nextRva)
      })
  | .movZeroExtend destination source width =>
      let value :=
        match source, width with
        | .memory addressing, 8 => symbolicRead8 state (addressing.expression state.registers)
        | .memory addressing, 16 => symbolicRead16 state (addressing.expression state.registers)
        | .register reg, 8 => .bitAnd (state.registers.get reg) (.constant 0xff)
        | .register reg, 16 => .bitAnd (state.registers.get reg) (.constant 0xffff)
        | .immediate value, 8 => .constant (value % 256)
        | .immediate value, 16 => .constant (value % 65536)
        | _, _ => .constant 0
      some (.next { state with registers := state.registers.set destination value })
  | .movSignExtend destination source width =>
      let value :=
        match source, width with
        | .memory addressing, 8 => symbolicRead8 state (addressing.expression state.registers)
        | .memory addressing, 16 => symbolicRead16 state (addressing.expression state.registers)
        | .register reg, 8 => .bitAnd (state.registers.get reg) (.constant 0xff)
        | .register reg, 16 => .bitAnd (state.registers.get reg) (.constant 0xffff)
        | .immediate value, 8 => .constant (value % 256)
        | .immediate value, 16 => .constant (value % 65536)
        | _, _ => .constant 0
      some (.next { state with registers := state.registers.set destination (value.signExtendNormalized width) })
  | .movFromOperandWidth width destination source =>
      let value := readOperandWidth width state source
      writeOperandWidth width state (.register destination) value |>.map InstructionResult.next
  | .movToOperandWidth width destination source =>
      let value := readOperandWidth width state (.register source)
      writeOperandWidth width state destination value |>.map InstructionResult.next
  | .movImmediateWidth width destination value =>
      writeOperandWidth width state destination (.constant value) |>.map InstructionResult.next
  | .binaryWidth width operation destination source => do
      let bits := width.bits
      let left := readOperandWidth width state destination
      let right := readOperandWidth width state source
      let rawResult :=
        match operation with
        | .add => Expr.addNormalized left right
        | .sub | .compare => Expr.subNormalized left right
        | .xor => Expr.xorNormalized left right
        | .and | .test => .bitAnd left right
        | .or => .bitOr left right
      let result := Expr.bitAnd rawResult (.constant (2 ^ bits - 1))
      let flags :=
        match operation with
        | .add => additionFlagsWidth bits left right result
        | .sub | .compare => subtractionFlagsWidth bits left right result
        | .xor | .and | .or | .test => logicalFlagsWidth undefinedSlot bits result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperandWidth width state destination result
      some (.next { next with flags := some flags })
  | .movFromOperand8 destination source =>
      some (.next (writeByteRegister state destination (readOperand8 state source)))
  | .movToOperand8 destination source =>
      writeOperand8 state destination (readByteRegister state source) |>.map InstructionResult.next
  | .movImmediate8 destination value =>
      writeOperand8 state destination (.constant value) |>.map InstructionResult.next
  | .binary8 operation destination source => do
      let left := readOperand8 state destination
      let right := readOperand8 state source
      let rawResult :=
        match operation with
        | .add => Expr.addNormalized left right
        | .sub | .compare => Expr.subNormalized left right
        | .xor => Expr.xorNormalized left right
        | .and | .test => .bitAnd left right
        | .or => .bitOr left right
      let result := Expr.bitAnd rawResult (.constant 0xff)
      let flags :=
        match operation with
        | .add => additionFlagsWidth 8 left right result
        | .sub | .compare => subtractionFlagsWidth 8 left right result
        | .xor | .and | .or | .test => logicalFlagsWidth undefinedSlot 8 result
      let next <-
        match operation with
        | .compare | .test => some state
        | _ => writeOperand8 state destination result
      some (.next { next with flags := some flags })
  | .conditionalMove condition destination source => do
      let flags <- state.flags
      let condition <- conditionExpression flags condition
      let selected := .ifEqual condition.toWord (.constant 1)
        (readOperand32 state source) (state.registers.get destination)
      some (.next { state with registers := state.registers.set destination selected })
  | .setCondition condition destination => do
      let flags <- state.flags
      let condition <- conditionExpression flags condition
      let value := .ifEqual condition.toWord (.constant 1)
        (.constant 1) (.constant 0)
      let next <- writeOperand8 state destination value
      some (.next next)
  | .exchange destination source => do
      let destinationValue := readOperand32 state destination
      let sourceValue := state.registers.get source
      let next <- writeOperand32 state destination sourceValue
      some (.next { next with registers := next.registers.set source destinationValue })
  | .convertWordToDword =>
      let value := (state.registers.get .eax).signExtendNormalized 16
      some (.next { state with registers := state.registers.set .eax value })
  | .convertDwordToQuad =>
      let value := .ifEqual (.bitValue (state.registers.get .eax) 31) (.constant 1)
        (.constant (2 ^ 32 - 1)) (.constant 0)
      some (.next { state with registers := state.registers.set .edx value })
  | .binaryCarry subtract destination source => do
      let flags <- state.flags
      let carryIn <- flags.carry
      let left := readOperand32 state destination
      let right := readOperand32 state source
      let carryValue := carryIn.toWord
      let result :=
        if subtract then
          Expr.subNormalized (Expr.subNormalized left right) carryValue
        else
          Expr.addNormalized (Expr.addNormalized left right) carryValue
      let next <- writeOperand32 state destination result
      let nextFlags := if subtract then sbbFlags left right result carryIn else adcFlags left right result carryIn
      some (.next { next with flags := some nextFlags })
  | .multiplyFull signed source =>
      let left := state.registers.get .eax
      let right := readOperand32 state source
      let low := Expr.multiply left right
      let high := if signed then Expr.multiplyHighSigned left right else Expr.multiplyHighUnsigned left right
      some (.next {
        state with
        registers := (state.registers.set .eax low).set .edx high
        flags := none
        comparison := none
      })
  | .multiplyLow destination source immediate =>
      let left := state.registers.get destination
      let right := immediate.map (fun value => Expr.constant value) |>.getD (readOperand32 state source)
      let left := if immediate.isSome then readOperand32 state source else left
      let result := Expr.multiply left right
      some (.next {
        state with
        registers := state.registers.set destination result
        flags := none
        comparison := none
      })
  | .doubleShift left destination source count => do
      let destinationValue := readOperand32 state destination
      let sourceValue := state.registers.get source
      let amount :=
        match count with
        | .immediate value => Expr.constant value
        | .cl => .bitAnd (state.registers.get .ecx) (.constant 0x1f)
      let inverse := Expr.subNormalized (.constant 32) amount
      let result :=
        if left then
          .bitOr (.shiftLeftBy destinationValue amount) (.shiftRightBy sourceValue inverse)
        else
          .bitOr (.shiftRightBy destinationValue amount) (.shiftLeftBy sourceValue inverse)
      let next <- writeOperand32 state destination result
      some (.next { next with flags := none, comparison := none })
  | .bitScan reverse destination source =>
      let value := readOperand32 state source
      let zero := BoolExpr.equal value (.constant 0)
      let result :=
        if reverse then
          .ifEqual value (.constant 0) (.undefined undefinedSlot)
            (.highestSetBit value)
        else
          .lowestSetBit value
      let flags : FlagsExpr :=
        if reverse then {
          zero := some zero
          carry := none
          auxiliary := some (.bit (.undefined undefinedSlot) 0)
          sign := none
          overflow := none
          parity := none
        } else {
          zero := some (.equal result (.constant 0))
          carry := some zero
          auxiliary := some (.bit (.undefined undefinedSlot) 0)
          sign := none
          overflow := none
          parity := none
        }
      some (.next {
        state with
        registers := state.registers.set destination result
        flags := some flags
        comparison := none
      })
  | .x87LoadStack index => do
      let value <- state.x87.get index
      some (.next { state with x87 := state.x87.push value })
  | .x87LoadConstant value =>
      some (.next { state with x87 := state.x87.push (.constant value) })
  | .x87Exchange index => do
      let top <- state.x87.get 0
      let other <- state.x87.get index
      let exchanged <- state.x87.set 0 other >>= fun next => next.set index top
      some (.next { state with x87 := exchanged })
  | .x87StoreStack index pop => do
      let top <- state.x87.get 0
      let stored <- state.x87.set index top
      let nextX87 <- if pop then stored.pop else some stored
      some (.next { state with x87 := nextX87 })
  | .x87Unary operation => do
      let top <- state.x87.get 0
      let value := X87Expr.unary operation top state.x87.control
      let nextX87 <- state.x87.set 0 value
      some (.next { state with x87 := nextX87 })
  | .x87BinaryStack operation destination source pop => do
      let left <- state.x87.get destination
      let right <- state.x87.get source
      let value := X87Expr.binary operation left right state.x87.control
      let updated <- state.x87.set destination value
      let nextX87 <- if pop then updated.pop else some updated
      some (.next { state with x87 := nextX87 })
  | .x87CompareStack index pop => do
      let left <- state.x87.get 0
      let right <- state.x87.get index
      let nextX87 <- if pop then state.x87.pop else some state.x87
      let falseFlag := BoolExpr.equal (.constant 0) (.constant 1)
      let flags : FlagsExpr := {
        zero := some (.equal (.x87CompareBit left right state.x87.control 2) (.constant 1))
        carry := some (.equal (.x87CompareBit left right state.x87.control 0) (.constant 1))
        auxiliary := some falseFlag
        sign := some falseFlag
        overflow := some falseFlag
        parity := some (.equal (.x87CompareBit left right state.x87.control 1) (.constant 1))
      }
      some (.next { state with x87 := nextX87, flags := some flags, comparison := none })
  | .x87LoadMemory format source =>
      let address := source.expression state.registers
      let value := x87LoadExpression pe format address state.x87.control
      some (.next { state with x87 := state.x87.push value })
  | .x87StoreMemory format destination pop => do
      let top <- state.x87.get 0
      let address := destination.expression state.registers
      let converted := X87Expr.store format top state.x87.control
      let next := state.write32 address (.x87Part converted 0)
      let next :=
        match format with
        | .float64 | .float80 => next.write32 (address.offset 4) (.x87Part converted 1)
        | .float32 | .int32 => next
      let destinationHigh : Operand32 := .memory {
        base := destination.base
        index := destination.index
        scaleShift := destination.scaleShift
        displacement := destination.displacement + 8
      }
      let next <-
        match format with
        | .float80 => writeOperandWidth .word next destinationHigh (Expr.x87Part converted 2)
        | .float32 => some next
        | .float64 => some next
        | .int32 => some next
      let nextX87 <- if pop then next.x87.pop else some next.x87
      some (.next { next with x87 := nextX87 })
  | .x87BinaryMemory operation format source => do
      let top <- state.x87.get 0
      let address := source.expression state.registers
      let right := x87LoadExpression pe format address state.x87.control
      let value := X87Expr.binary operation top right state.x87.control
      let nextX87 <- state.x87.set 0 value
      some (.next { state with x87 := nextX87 })
  | .x87LoadControl source =>
      let control := symbolicRead16 state (source.expression state.registers)
      some (.next { state with x87 := { state.x87 with control } })
  | .x87StoreControl destination => do
      let next <- writeOperandWidth .word state (.memory destination) state.x87.control
      some (.next next)
  | .x87Initialize =>
      some (.next { state with x87 := {
        stack := []
        control := .constant 0x037f
        status := .constant 0
      } })
  | .x87StoreStatusAx => do
      let next <- writeOperandWidth .word state (.register .eax) state.x87.status
      some (.next next)
  | .x87Examine => do
      let top <- state.x87.get 0
      some (.next { state with x87 := {
        state.x87 with status := .x87ExamineStatus top state.x87.status
      } })
  | .moveDwords repeated =>
      let destination := state.registers.edi
      let source := state.registers.esi
      let count := if repeated then state.registers.ecx else Expr.constant 1
      let direction := BoolExpr.inputFlag 10
      let distance := Expr.multiply count (.constant 4)
      let nextDestination := .ifEqual direction.toWord (.constant 1)
        (Expr.subNormalized destination distance) (Expr.addNormalized destination distance)
      let nextSource := .ifEqual direction.toWord (.constant 1)
        (Expr.subNormalized source distance) (Expr.addNormalized source distance)
      let registers := (state.registers.set .edi nextDestination).set .esi nextSource
      let registers := if repeated then registers.set .ecx (.constant 0) else registers
      some (.stop {
        state with
        registers
        outcome := some (.bulkCopy { destination, source, count, direction } nextRva)
      })
  | .callIndirect target =>
      let target := readOperand32 state target
      let stack := state.registers.esp.offset (2 ^ 32 - 4)
      let state := state.write32 stack (.constant (pe.imageBase + nextRva))
      some (.stop {
        state with
        registers := state.registers.set .esp stack
        outcome := some (.indirectCall target nextRva (pe.imageBase + nextRva))
      })
  | .jumpIndirect target =>
      some (.stop { state with outcome := some (.indirectJump (readOperand32 state target)) })
  | .divideUnsigned source =>
      let high := state.registers.edx
      let low := state.registers.eax
      let divisor := readOperand32 state source
      let valid := BoolExpr.divisionValid high low divisor
      let quotient := Expr.ifEqual valid.toWord (.constant 1)
        (.divideQuotient high low divisor) (.undefined undefinedSlot)
      let remainder := Expr.ifEqual valid.toWord (.constant 1)
        (.divideRemainder high low divisor) (.undefined (undefinedSlot + 1))
      some (.stop {
        state with
        registers := (state.registers.set .eax quotient).set .edx remainder
        flags := none
        comparison := none
        outcome := some (.checkedContinue valid nextRva)
      })
  | .atomicCompareExchange destination source =>
      let address := destination.expression state.registers
      let expected := state.registers.eax
      let replacement := state.registers.get source
      let observed := symbolicRead32 state address
      let written := Expr.ifEqual expected observed replacement observed
      let next := state.write32 address written
      let accumulator := Expr.ifEqual expected observed expected observed
      let result := Expr.subNormalized expected observed
      some (.stop {
        next with
        registers := next.registers.set .eax accumulator
        flags := some (subtractionFlags expected observed result)
        comparison := some (expected, observed)
        outcome := some (.atomicCompareExchange address expected replacement nextRva)
      })

def executeCode (pe : PE32) (imports : List PEImport) :
    Nat -> Nat -> Nat -> Bytes -> SymbolicBehavior -> Option (SymbolicBehavior × Bytes)
  | 0, _, _, _, _ => none
  | _ + 1, _, _, [], state => some (state, [])
  | fuel + 1, undefinedSlot, pc, bytes, state => do
      let decoded <- decodeInstructionExact bytes
      let result <- executeInstruction pe imports pc undefinedSlot decoded state
      match result with
      | .next nextState => executeCode pe imports fuel (undefinedSlot + 1) (pc + decoded.size) decoded.trailing nextState
      | .stop finalState => pure (finalState, decoded.trailing)

def paddingByte (byte : Byte) : Bool :=
  byte == 0 || byte == 0x90

def paddingBytes : Bytes -> Bool
  | [] => true
  | 0x00 :: tail => paddingBytes tail
  | 0x90 :: tail => paddingBytes tail
  | 0x66 :: 0x90 :: tail => paddingBytes tail
  | 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0x76 :: 0x00 :: tail => paddingBytes tail
  | 0x2e :: 0x8d :: 0x74 :: 0x26 :: 0x00 :: tail => paddingBytes tail
  | 0x2e :: 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0xb6 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0x8d :: 0xb4 :: 0x26 :: 0x00 :: 0x00 :: 0x00 :: 0x00 :: tail => paddingBytes tail
  | 0xeb :: displacement :: tail => displacement == tail.length && paddingBytes tail
  | _ => false

def decodeEntryBehavior (pe : PE32) (bytes : Bytes) : Option SymbolicBehavior := do
  let imports <- parseImports pe
  let (behavior, trailing) <- executeCode pe imports (bytes.length + 1) 0 pe.entrypointRva bytes initialSymbolic
  if behavior.outcome.isSome && paddingBytes trailing then
    pure behavior
  else
    none

structure LoaderShape where
  entrypointRva : Nat
  imageBase : Nat
  sectionAlignment : Nat
  fileAlignment : Nat
  sizeOfImage : Nat
  sizeOfHeaders : Nat
  executableVirtualAddress : Nat
  sections : List Section
  imports : List PEImport
  relocations : List BaseRelocation
deriving Repr, DecidableEq

def executableEntrySection (pe : PE32) : Option Section :=
  match pe.sections.filter (fun sec =>
    sec.executable && sec.virtualAddress <= pe.entrypointRva && pe.entrypointRva < sec.virtualAddress + sec.mappedSize) with
  | [sec] => some sec
  | _ => none

def loaderShape (pe : PE32) : Option LoaderShape := do
  let sec <- executableEntrySection pe
  let imports <- parseImports pe
  let relocations <- parseRelocations pe
  pure {
    entrypointRva := pe.entrypointRva,
    imageBase := pe.imageBase,
    sectionAlignment := pe.sectionAlignment,
    fileAlignment := pe.fileAlignment,
    sizeOfImage := pe.sizeOfImage,
    sizeOfHeaders := pe.sizeOfHeaders,
    executableVirtualAddress := sec.virtualAddress,
    sections := pe.sections,
    imports,
    relocations,
  }

def imageBehavior (bytes : Bytes) : Option SymbolicBehavior := do
  let pe <- parsePE32 bytes
  let _ <- loaderShape pe
  let sec <- executableEntrySection pe
  let code <- sectionBytes pe sec
  decodeEntryBehavior pe (code.drop (pe.entrypointRva - sec.virtualAddress))

def runImage (bytes : Bytes) (state : MachineState) : Option ConcreteBehavior :=
  (imageBehavior bytes).map (fun behavior => behavior.eval state)

def StrongRefines (original candidate : Bytes) : Prop :=
  forall state, runImage candidate state = runImage original state

def bundleEligible (original candidate : Bytes) : Bool :=
  match parsePE32 original, parsePE32 candidate with
  | some originalPe, some candidatePe =>
      decide (loaderShape originalPe = loaderShape candidatePe) &&
      decide (imageBehavior candidate = imageBehavior original) &&
      (imageBehavior original).isSome
  | _, _ => false

def checkBundle (original candidate : Bytes) : Bool :=
  bundleEligible original candidate

theorem checkBundle_sound (original candidate : Bytes)
    (checked : checkBundle original candidate = true) :
    StrongRefines original candidate := by
  unfold checkBundle bundleEligible at checked
  split at checked <;> try contradiction
  rename_i originalPe candidatePe originalParsed candidateParsed
  simp only [Bool.and_eq_true, decide_eq_true_eq] at checked
  have behaviorEqual : imageBehavior candidate = imageBehavior original := checked.1.2
  intro state
  simp only [runImage, behaviorEqual]

structure Span where
  start : Nat
  size : Nat
deriving Repr, DecidableEq

def Span.stop (span : Span) : Nat :=
  span.start + span.size

structure RegionPair where
  original : Span
  candidate : Span
  root : Bool
deriving Repr, DecidableEq

structure ProofBundle where
  originalBytes : Bytes
  candidateBytes : Bytes
  regions : List RegionPair
  originalPadding : List Span
  candidatePadding : List Span
deriving Repr, DecidableEq

def spanBytes (pe : PE32) (span : Span) : Option Bytes := do
  let sec <- pe.sections.find? (fun sec =>
    sec.executable && sec.virtualAddress <= span.start && span.stop <= sec.virtualAddress + sec.mappedSize)
  let offset := span.start - sec.virtualAddress
  if offset + span.size > sec.mappedSize then none else
  let rawCount := if offset < sec.rawSize then min span.size (sec.rawSize - offset) else 0
  let raw <- pe.bytes.readBytes (sec.rawPointer + offset) rawCount
  pure (raw ++ List.replicate (span.size - rawCount) 0)

def regionBehaviorWithImports (pe : PE32) (imports : List PEImport)
    (span : Span) : Option SymbolicBehavior := do
  let bytes <- spanBytes pe span
  let (behavior, trailing) <- executeCode pe imports (bytes.length + 1) 0 span.start bytes initialSymbolic
  if !trailing.isEmpty then none else
  if behavior.outcome.isSome then pure behavior else
  pure { behavior with outcome := some (.jump span.stop) }

def regionBehavior (pe : PE32) (span : Span) : Option SymbolicBehavior := do
  let imports <- parseImports pe
  regionBehaviorWithImports pe imports span

inductive LogicalOutcomeExpr where
  | returned (target : Expr)
  | jump (targetRegion : Nat)
  | branch (condition : BoolExpr) (trueTargetRegion falseTargetRegion : Nat)
  | call (targetRegion returnRegion returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Expr) (returnRegion : Nat)
  | externalJump (imported : PEImport) (arguments : List Expr)
deriving Repr, DecidableEq

structure LogicalBehavior where
  registers : Registers Expr
  x87 : SymbolicX87State
  writes : List (Expr × Expr)
  flags : Option FlagsExpr
  outcome : LogicalOutcomeExpr
deriving Repr, DecidableEq

inductive LogicalConcreteOutcome where
  | returned (target : Word)
  | jump (targetRegion : Nat)
  | branch (condition : Bool) (trueTargetRegion falseTargetRegion : Nat)
  | call (targetRegion returnRegion returnAddress : Nat)
  | externalCall (imported : PEImport) (arguments : List Word) (returnRegion : Nat)
  | externalJump (imported : PEImport) (arguments : List Word)

structure LogicalConcreteBehavior where
  registers : Registers Word
  x87 : ConcreteX87State
  memory : Memory
  eflags : Word
  outcome : LogicalConcreteOutcome

def findRegionIndex (candidate : Bool) (targetRva : Nat) : List RegionPair -> Nat -> Option Nat
  | [], _ => none
  | region :: tail, index =>
      let start := if candidate then region.candidate.start else region.original.start
      if start == targetRva then some index else findRegionIndex candidate targetRva tail (index + 1)

def normalizeOutcome (regions : List RegionPair) (candidate : Bool) : OutcomeExpr -> Option LogicalOutcomeExpr
  | .returned target => some (.returned target)
  | .jump targetRva => do
      let target <- findRegionIndex candidate targetRva regions 0
      pure (.jump target)
  | .branch condition trueTargetRva falseTargetRva => do
      let trueTarget <- findRegionIndex candidate trueTargetRva regions 0
      let falseTarget <- findRegionIndex candidate falseTargetRva regions 0
      pure (.branch condition trueTarget falseTarget)
  | .call targetRva returnRva returnAddress => do
      let target <- findRegionIndex candidate targetRva regions 0
      let continuation <- findRegionIndex candidate returnRva regions 0
      pure (.call target continuation returnAddress)
  | .externalCall imported arguments returnRva => do
      let continuation <- findRegionIndex candidate returnRva regions 0
      pure (.externalCall imported arguments continuation)
  | .externalJump imported arguments =>
      pure (.externalJump imported arguments)
  | .bulkCopy _ _ => none
  | .indirectCall _ _ _ => none
  | .indirectJump _ => none
  | .checkedContinue _ _ => none
  | .atomicCompareExchange _ _ _ _ => none

def normalizeBehavior (regions : List RegionPair) (candidate : Bool) (behavior : SymbolicBehavior) : Option LogicalBehavior := do
  let outcomeExpr <- behavior.outcome
  let outcome <- normalizeOutcome regions candidate outcomeExpr
  pure {
    registers := behavior.registers
    x87 := behavior.x87
    writes := behavior.writes
    flags := behavior.flags
    outcome
  }

def originalRegionBehaviors (pe : PE32) (regions : List RegionPair) : List (Option LogicalBehavior) :=
  regions.map (fun region => (regionBehavior pe region.original).bind (normalizeBehavior regions false))

def candidateRegionBehaviors (pe : PE32) (regions : List RegionPair) : List (Option LogicalBehavior) :=
  regions.map (fun region => (regionBehavior pe region.candidate).bind (normalizeBehavior regions true))

def LogicalBehavior.eval (behavior : LogicalBehavior) (state : MachineState) : LogicalConcreteBehavior := {
  registers := {
    eax := behavior.registers.eax.eval state,
    ebx := behavior.registers.ebx.eval state,
    ecx := behavior.registers.ecx.eval state,
    edx := behavior.registers.edx.eval state,
    esi := behavior.registers.esi.eval state,
    edi := behavior.registers.edi.eval state,
    ebp := behavior.registers.ebp.eval state,
    esp := behavior.registers.esp.eval state,
  },
  x87 := {
    stack := behavior.x87.stack.map (X87Expr.eval state)
    control := (behavior.x87.control.eval state).extractLsb' 0 16
    status := (behavior.x87.status.eval state).extractLsb' 0 16
  }
  memory := applyWrites state behavior.writes,
  eflags := behavior.flags.map (FlagsExpr.eval state) |>.getD state.eflags
  outcome := match behavior.outcome with
    | .returned target => .returned (target.eval state)
    | .jump targetRegion => .jump targetRegion
    | .branch condition trueTargetRegion falseTargetRegion =>
        .branch (condition.eval state) trueTargetRegion falseTargetRegion
    | .call targetRegion returnRegion returnAddress => .call targetRegion returnRegion returnAddress
    | .externalCall imported arguments returnRegion =>
        .externalCall imported (arguments.map (Expr.eval state)) returnRegion
    | .externalJump imported arguments =>
        .externalJump imported (arguments.map (Expr.eval state)),
}

def insertSpan (span : Span) : List Span -> List Span
  | [] => [span]
  | head :: tail =>
      if span.start <= head.start then span :: head :: tail else head :: insertSpan span tail

def sortSpans (spans : List Span) : List Span :=
  spans.foldr insertSpan []

def spansCoverFrom : Nat -> Nat -> List Span -> Bool
  | cursor, stop, [] => cursor == stop
  | cursor, stop, span :: tail =>
      span.size > 0 && span.start == cursor && span.stop <= stop && spansCoverFrom span.stop stop tail

def spansInSection (sec : Section) (spans : List Span) : List Span :=
  spans.filter (fun span => sec.virtualAddress <= span.start && span.stop <= sec.virtualAddress + sec.mappedSize)

def spanInExecutableSection (pe : PE32) (span : Span) : Bool :=
  pe.sections.any (fun sec =>
    sec.executable && span.size > 0 && sec.virtualAddress <= span.start && span.stop <= sec.virtualAddress + sec.mappedSize)

def executableCoverageClosed (pe : PE32) (spans : List Span) : Bool :=
  spans.all (spanInExecutableSection pe) &&
  (pe.sections.filter (fun sec => sec.executable)).all (fun sec =>
    spansCoverFrom sec.virtualAddress (sec.virtualAddress + sec.mappedSize) (sortSpans (spansInSection sec spans)))

def paddingSpanValid (pe : PE32) (span : Span) : Bool :=
  match spanBytes pe span with
  | some bytes => paddingBytes bytes
  | none => false

def entryRegionMatches (originalPe candidatePe : PE32) (region : RegionPair) : Bool :=
  region.root && region.original.start == originalPe.entrypointRva && region.candidate.start == candidatePe.entrypointRva

def rootCoverageClosed (originalPe candidatePe : PE32) (regions : List RegionPair) : Bool :=
  regions.any (entryRegionMatches originalPe candidatePe)

def proofBundleEligible (bundle : ProofBundle) : Bool :=
  match parsePE32 bundle.originalBytes, parsePE32 bundle.candidateBytes with
  | some originalPe, some candidatePe =>
      (loaderShape originalPe).isSome &&
      (loaderShape candidatePe).isSome &&
      decide (loaderShape originalPe = loaderShape candidatePe) &&
      (originalRegionBehaviors originalPe bundle.regions).all Option.isSome &&
      bundle.regions.length > 0 &&
      executableCoverageClosed originalPe (bundle.regions.map (fun region => region.original) ++ bundle.originalPadding) &&
      executableCoverageClosed candidatePe (bundle.regions.map (fun region => region.candidate) ++ bundle.candidatePadding) &&
      bundle.originalPadding.all (paddingSpanValid originalPe) &&
      bundle.candidatePadding.all (paddingSpanValid candidatePe) &&
      rootCoverageClosed originalPe candidatePe bundle.regions &&
      decide (candidateRegionBehaviors candidatePe bundle.regions = originalRegionBehaviors originalPe bundle.regions)
  | _, _ => false

def checkProofBundle (bundle : ProofBundle) : Bool :=
  proofBundleEligible bundle

def runLogicalRegions (pe : PE32) (regions : List RegionPair) (candidate : Bool)
    (state : MachineState) : List (Option LogicalConcreteBehavior) :=
  let behaviors := if candidate then candidateRegionBehaviors pe regions else originalRegionBehaviors pe regions
  behaviors.map (Option.map (fun behavior => behavior.eval state))

def StrongRefinesBundle (bundle : ProofBundle) : Prop :=
  forall originalPe candidatePe,
    parsePE32 bundle.originalBytes = some originalPe ->
    parsePE32 bundle.candidateBytes = some candidatePe ->
    forall state,
      runLogicalRegions candidatePe bundle.regions true state =
      runLogicalRegions originalPe bundle.regions false state

theorem checkProofBundle_sound (bundle : ProofBundle)
    (checked : checkProofBundle bundle = true) :
    StrongRefinesBundle bundle := by
  unfold checkProofBundle proofBundleEligible at checked
  split at checked <;> try contradiction
  rename_i parsedOriginal parsedCandidate originalParsed candidateParsed
  simp only [Bool.and_eq_true, decide_eq_true_eq] at checked
  have symbolicEqual :
      candidateRegionBehaviors parsedCandidate bundle.regions =
      originalRegionBehaviors parsedOriginal bundle.regions := checked.2
  intro originalPe candidatePe originalEq candidateEq state
  have originalPeEq : originalPe = parsedOriginal := by
    rw [originalParsed] at originalEq
    exact Option.some.inj originalEq.symm
  have candidatePeEq : candidatePe = parsedCandidate := by
    rw [candidateParsed] at candidateEq
    exact Option.some.inj candidateEq.symm
  subst originalPe
  subst candidatePe
  change
    List.map (Option.map (fun behavior => behavior.eval state))
        (candidateRegionBehaviors parsedCandidate bundle.regions) =
      List.map (Option.map (fun behavior => behavior.eval state))
        (originalRegionBehaviors parsedOriginal bundle.regions)
  exact congrArg (List.map (Option.map (fun behavior => behavior.eval state))) symbolicEqual

structure ExternalEvent where
  imported : PEImport
  state : MachineState

structure Environment where
  result : Nat -> ExternalEvent -> MachineState

def applyEnvironment (environment : Environment) (index : Nat) (event : ExternalEvent)
    : MachineState := environment.result index event

structure CallFrame where
  returnRegion : Nat
  returnAddress : Word

inductive Execution where
  | running (region : Nat) (state : MachineState) (calls : List CallFrame)
      (eventIndex : Nat) (events : List ExternalEvent)
  | returned (target : Word) (state : MachineState) (events : List ExternalEvent)
  | fault

def behaviorAt (behaviors : List (Option LogicalBehavior)) (index : Nat) : Option LogicalBehavior :=
  (behaviors.drop index).head?.join

def stepExecution (environment : Environment) (behaviors : List (Option LogicalBehavior)) : Execution -> Execution
  | .running region state calls eventIndex events =>
      match behaviorAt behaviors region with
      | none => .fault
      | some behavior =>
          let concrete := behavior.eval state
          let nextState : MachineState := {
            registers := concrete.registers
            memory := concrete.memory
            undefinedValue := state.undefinedValue
            x87 := {
              stack := fun index =>
                (concrete.x87.stack.drop index).head?.getD (BitVec.ofNat 80 0)
              control := concrete.x87.control
              status := concrete.x87.status
            }
            eflags := concrete.eflags
            fsBase := state.fsBase
          }
          match concrete.outcome with
          | .returned target =>
              match calls with
              | [] => .returned target nextState events
              | frame :: tail =>
                  if target == frame.returnAddress then
                    .running frame.returnRegion nextState tail eventIndex events
                  else
                    .fault
          | .jump targetRegion => .running targetRegion nextState calls eventIndex events
          | .branch condition trueTargetRegion falseTargetRegion =>
              .running (if condition then trueTargetRegion else falseTargetRegion) nextState calls eventIndex events
          | .call targetRegion returnRegion returnAddress =>
              .running targetRegion nextState
                ({ returnRegion, returnAddress := BitVec.ofNat 32 returnAddress } :: calls) eventIndex events
          | .externalCall imported arguments returnRegion =>
              let _ := arguments
              let event := { imported, state := nextState }
              let result := applyEnvironment environment eventIndex event
              .running returnRegion result calls (eventIndex + 1) (events ++ [event])
          | .externalJump imported arguments =>
              let _ := arguments
              let event := { imported, state := nextState }
              let result := applyEnvironment environment eventIndex event
              match calls with
              | [] => .returned (BitVec.ofNat 32 0) result (events ++ [event])
              | frame :: tail =>
                  .running frame.returnRegion result tail (eventIndex + 1) (events ++ [event])
  | terminal => terminal

def executeFuel (environment : Environment) (behaviors : List (Option LogicalBehavior)) : Nat -> Execution -> Execution
  | 0, execution => execution
  | fuel + 1, execution => executeFuel environment behaviors fuel (stepExecution environment behaviors execution)

def entryRegionIndex (originalPe candidatePe : PE32) : List RegionPair -> Nat -> Option Nat
  | [], _ => none
  | region :: tail, index =>
      if entryRegionMatches originalPe candidatePe region then
        some index
      else
        entryRegionIndex originalPe candidatePe tail (index + 1)

theorem rootCoverage_entryRegionIndex_isSome (originalPe candidatePe : PE32)
    (regions : List RegionPair) (index : Nat)
    (closed : rootCoverageClosed originalPe candidatePe regions = true) :
    (entryRegionIndex originalPe candidatePe regions index).isSome = true := by
  induction regions generalizing index with
  | nil => simp [rootCoverageClosed] at closed
  | cons region tail ih =>
      unfold rootCoverageClosed at closed
      simp only [List.any_cons, Bool.or_eq_true] at closed
      unfold entryRegionIndex
      by_cases hmatch : entryRegionMatches originalPe candidatePe region = true
      · simp [hmatch]
      · simp [hmatch]
        apply ih
        exact closed.resolve_left hmatch

def StrongTraceRefines (bundle : ProofBundle) : Prop :=
  forall originalPe candidatePe,
    parsePE32 bundle.originalBytes = some originalPe ->
    parsePE32 bundle.candidateBytes = some candidatePe ->
    forall environment state fuel start,
      start < bundle.regions.length ->
      executeFuel environment (candidateRegionBehaviors candidatePe bundle.regions) fuel (.running start state [] 0 []) =
      executeFuel environment (originalRegionBehaviors originalPe bundle.regions) fuel (.running start state [] 0 [])

theorem checkProofBundle_trace_sound (bundle : ProofBundle)
    (checked : checkProofBundle bundle = true) :
    StrongTraceRefines bundle := by
  unfold checkProofBundle proofBundleEligible at checked
  split at checked <;> try contradiction
  rename_i parsedOriginal parsedCandidate originalParsed candidateParsed
  simp only [Bool.and_eq_true, decide_eq_true_eq] at checked
  have symbolicEqual :
      candidateRegionBehaviors parsedCandidate bundle.regions =
      originalRegionBehaviors parsedOriginal bundle.regions := checked.2
  intro originalPe candidatePe originalEq candidateEq environment state fuel start _
  have originalPeEq : originalPe = parsedOriginal := by
    rw [originalParsed] at originalEq
    exact Option.some.inj originalEq.symm
  have candidatePeEq : candidatePe = parsedCandidate := by
    rw [candidateParsed] at candidateEq
    exact Option.some.inj candidateEq.symm
  subst originalPe
  subst candidatePe
  rw [symbolicEqual]

def ExactImageStrongRefinement (bundle : ProofBundle) : Prop :=
  checkProofBundle bundle = true ∧ StrongRefinesBundle bundle ∧ StrongTraceRefines bundle

theorem checkProofBundle_guarantee (bundle : ProofBundle)
    (checked : checkProofBundle bundle = true) :
    ExactImageStrongRefinement bundle :=
  And.intro checked (And.intro (checkProofBundle_sound bundle checked) (checkProofBundle_trace_sound bundle checked))

end StageA.Formal
