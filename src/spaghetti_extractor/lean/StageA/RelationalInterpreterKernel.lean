import StageA.RelationalEngine
import StageA.RelationalExecution
import StageA.RelationalInterpreter
import StageA.RelationalPEExecution

namespace StageA.Relational.InterpreterKernel

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.Interpreter

/-! This module is the trust boundary between a compiled, freestanding Stage B
interpreter and `RelationalInterpreter`.  Generated Python data can locate
ranges and propose control flow, but every authoritative fact below is either
recomputed from the exact PE bytes or supplied as a Lean proposition. -/

/-! A reviewed SHA-256 implementation used only for immutable artifact
bindings. Exact PE and range bytes remain the semantic authority. -/
namespace KernelSHA256

def modulus : Nat := 4294967296
def mask : Nat := 4294967295

def word (value : Nat) : Nat := value % modulus
def add (left right : Nat) : Nat := word (left + right)
def add4 (a b c d : Nat) : Nat := add (add a b) (add c d)
def add5 (a b c d e : Nat) : Nat := add (add4 a b c d) e
def xor (left right : Nat) : Nat := Nat.xor left right
def xor3 (a b c : Nat) : Nat := xor (xor a b) c
def band (left right : Nat) : Nat := left &&& right
def bnot (value : Nat) : Nat := xor value mask
def shr (value amount : Nat) : Nat := value >>> amount

def rotr (value amount : Nat) : Nat :=
  if amount = 0 then word value else
    word ((value >>> amount) ||| (value <<< (32 - amount)))

def choose (x y z : Nat) : Nat := xor (band x y) (band (bnot x) z)
def majority (x y z : Nat) : Nat := xor3 (band x y) (band x z) (band y z)
def bigSigma0 (x : Nat) : Nat := xor3 (rotr x 2) (rotr x 13) (rotr x 22)
def bigSigma1 (x : Nat) : Nat := xor3 (rotr x 6) (rotr x 11) (rotr x 25)
def smallSigma0 (x : Nat) : Nat := xor3 (rotr x 7) (rotr x 18) (shr x 3)
def smallSigma1 (x : Nat) : Nat := xor3 (rotr x 17) (rotr x 19) (shr x 10)

def constants : List Nat := [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def initial : List Nat := [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def u64be (value : Nat) : Bytes :=
  [(value >>> 56) % 256, (value >>> 48) % 256, (value >>> 40) % 256,
   (value >>> 32) % 256, (value >>> 24) % 256, (value >>> 16) % 256,
   (value >>> 8) % 256, value % 256]

def pad (bytes : Bytes) : Bytes :=
  let withMarker := bytes ++ [128]
  let zeroCount := (56 + 64 - withMarker.length % 64) % 64
  withMarker ++ List.replicate zeroCount 0 ++
    u64be ((bytes.length * 8) % 18446744073709551616)

def readWord (bytes : Bytes) (offset : Nat) : Nat :=
  ((bytes.getD offset 0) <<< 24) + ((bytes.getD (offset + 1) 0) <<< 16) +
    ((bytes.getD (offset + 2) 0) <<< 8) + bytes.getD (offset + 3) 0

def seedSchedule (chunk : Bytes) : List Nat :=
  (List.range 16).map fun index => readWord chunk (index * 4)

def extendSchedule : Nat -> List Nat -> List Nat
  | 0, words => words
  | fuel + 1, words =>
      let index := words.length
      let next := add4 (smallSigma1 (words.getD (index - 2) 0))
        (words.getD (index - 7) 0)
        (smallSigma0 (words.getD (index - 15) 0))
        (words.getD (index - 16) 0)
      extendSchedule fuel (words ++ [next])

structure RoundState where
  a : Nat
  b : Nat
  c : Nat
  d : Nat
  e : Nat
  f : Nat
  g : Nat
  h : Nat
deriving Repr, DecidableEq

def round (state : RoundState) (constant schedule : Nat) : RoundState :=
  let t1 := add5 state.h (bigSigma1 state.e)
    (choose state.e state.f state.g) constant schedule
  let t2 := add (bigSigma0 state.a) (majority state.a state.b state.c)
  { a := add t1 t2, b := state.a, c := state.b, d := state.c,
    e := add state.d t1, f := state.e, g := state.f, h := state.g }

def runRounds : List (Nat × Nat) -> RoundState -> RoundState
  | [], state => state
  | item :: tail, state => runRounds tail (round state item.1 item.2)

def compress (hash chunk : List Nat) : List Nat :=
  let start : RoundState := {
    a := hash.getD 0 0, b := hash.getD 1 0, c := hash.getD 2 0,
    d := hash.getD 3 0, e := hash.getD 4 0, f := hash.getD 5 0,
    g := hash.getD 6 0, h := hash.getD 7 0 }
  let schedule := extendSchedule 48 (seedSchedule chunk)
  let result := runRounds (List.zip constants schedule) start
  [add (hash.getD 0 0) result.a, add (hash.getD 1 0) result.b,
   add (hash.getD 2 0) result.c, add (hash.getD 3 0) result.d,
   add (hash.getD 4 0) result.e, add (hash.getD 5 0) result.f,
   add (hash.getD 6 0) result.g, add (hash.getD 7 0) result.h]

def chunks : Nat -> Bytes -> List Bytes
  | 0, _ => []
  | fuel + 1, bytes =>
      if bytes.isEmpty then [] else bytes.take 64 :: chunks fuel (bytes.drop 64)

def wordBytes (value : Nat) : Bytes :=
  [value >>> 24, (value >>> 16) % 256, (value >>> 8) % 256, value % 256]

def digest (bytes : Bytes) : Bytes :=
  let padded := pad bytes
  let final := (chunks (padded.length / 64 + 1) padded).foldl compress initial
  final.flatMap wordBytes

def hexDigit : Nat -> Char
  | 0 => '0' | 1 => '1' | 2 => '2' | 3 => '3'
  | 4 => '4' | 5 => '5' | 6 => '6' | 7 => '7'
  | 8 => '8' | 9 => '9' | 10 => 'a' | 11 => 'b'
  | 12 => 'c' | 13 => 'd' | 14 => 'e' | _ => 'f'

def hexByte (value : Nat) : List Char :=
  [hexDigit ((value / 16) % 16), hexDigit (value % 16)]

def hex (bytes : Bytes) : String :=
  String.ofList ((digest bytes).flatMap hexByte)

def inputValid (bytes : Bytes) : Bool := bytes.all (fun byte => byte < 256)

def checkedHex (bytes : Bytes) (claimed : String) : Bool :=
  inputValid bytes && hex bytes == claimed

end KernelSHA256

/-- Read an exact immutable mapped-image range.  Unlike `spanBytes`, this is
not restricted to executable sections, so it can bind the interpreter program
and engine layout in read-only data. -/
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

structure ImmutableArtifactRange where
  role : String
  span : Span
  bytes : Bytes
  sha256 : String
deriving Repr, DecidableEq

def ImmutableArtifactRange.checked (pe : PE32)
    (range : ImmutableArtifactRange) : Bool :=
  range.span.size == range.bytes.length &&
    immutableMappedBytes pe range.span == some range.bytes &&
    KernelSHA256.checkedHex range.bytes range.sha256

def ImmutableArtifactRange.Valid (pe : PE32)
    (range : ImmutableArtifactRange) : Prop :=
  range.span.size = range.bytes.length ∧
    immutableMappedBytes pe range.span = some range.bytes ∧
    KernelSHA256.checkedHex range.bytes range.sha256 = true

theorem ImmutableArtifactRange.checked_iff_valid (pe : PE32)
    (range : ImmutableArtifactRange) :
    range.checked pe = true ↔ range.Valid pe := by
  simp [ImmutableArtifactRange.checked, ImmutableArtifactRange.Valid,
    and_assoc]

/-- A proof-oriented compiler profile.  This is a decomposition constraint,
not a compiler-correctness assumption: all generated code is still decoded and
proved from the PE. -/
inductive ProofCompilerProfile where
  | o0NoInlineFramePointer
deriving Repr, DecidableEq

/-- Exact artifact identities.  `candidatePeBytes` is a tree so large images do
not force a single enormous Lean list expression.  The PE digest is audit
metadata only; the parsed tree itself is authoritative.  Program and layout
digests are checked in Lean and their compiled ranges are independently read
back from the parsed PE. -/
structure KernelArtifactBinding where
  compilerProfile : ProofCompilerProfile
  candidatePeBytes : ByteTree
  candidatePeSha256 : String
  programManifestBytes : Bytes
  programManifestSha256 : String
  compiledProgramBytes : Bytes
  compiledProgramSha256 : String
  compiledProgramRanges : List ImmutableArtifactRange
  engineLayoutBytes : Bytes
  engineLayoutSha256 : String
  engineLayoutRange : ImmutableArtifactRange
deriving Repr, DecidableEq

def KernelArtifactBinding.checked (binding : KernelArtifactBinding)
    (pe : PE32) : Bool :=
  binding.compilerProfile == .o0NoInlineFramePointer &&
    parsePE32Tree binding.candidatePeBytes == some pe &&
    KernelSHA256.checkedHex binding.programManifestBytes
      binding.programManifestSha256 &&
    KernelSHA256.checkedHex binding.compiledProgramBytes
      binding.compiledProgramSha256 &&
    binding.compiledProgramBytes ==
      binding.compiledProgramRanges.flatMap (fun range => range.bytes) &&
    binding.compiledProgramRanges.all (·.checked pe) &&
    KernelSHA256.checkedHex binding.engineLayoutBytes binding.engineLayoutSha256 &&
    binding.engineLayoutRange.bytes == binding.engineLayoutBytes &&
    binding.engineLayoutRange.checked pe

def KernelArtifactBinding.Valid (binding : KernelArtifactBinding)
    (pe : PE32) : Prop :=
  binding.compilerProfile = .o0NoInlineFramePointer ∧
    parsePE32Tree binding.candidatePeBytes = some pe ∧
    KernelSHA256.checkedHex binding.programManifestBytes
      binding.programManifestSha256 = true ∧
    KernelSHA256.checkedHex binding.compiledProgramBytes
      binding.compiledProgramSha256 = true ∧
    binding.compiledProgramBytes =
      binding.compiledProgramRanges.flatMap (fun range => range.bytes) ∧
    (∀ range ∈ binding.compiledProgramRanges, range.Valid pe) ∧
    KernelSHA256.checkedHex binding.engineLayoutBytes binding.engineLayoutSha256 = true ∧
    binding.engineLayoutRange.bytes = binding.engineLayoutBytes ∧
    binding.engineLayoutRange.Valid pe

theorem KernelArtifactBinding.checked_iff_valid
    (binding : KernelArtifactBinding) (pe : PE32) :
    binding.checked pe = true ↔ binding.Valid pe := by
  simp [KernelArtifactBinding.checked, KernelArtifactBinding.Valid,
    ImmutableArtifactRange.checked_iff_valid, and_assoc]

structure KernelInstruction where
  rva : Nat
  bytes : Bytes
deriving Repr, DecidableEq

/-- Re-decode exactly the bytes fetched from the candidate image. -/
def KernelInstruction.decode? (pe : PE32)
    (instruction : KernelInstruction) : Option DecodedInstruction := do
  if instruction.bytes.isEmpty || instruction.bytes.length > 15 then none else
  let exact <- spanBytes pe
    { start := instruction.rva, size := instruction.bytes.length }
  if exact != instruction.bytes then none else
  let fetched <- executableInstructionWindow pe instruction.rva
  let decoded <- decodeInstructionExact fetched
  if decoded.size != instruction.bytes.length ||
      fetched.take decoded.size != instruction.bytes then none else
  some decoded

/-- The current reviewed symbolic x86 semantics must cover the decoded form.
This is deliberately stronger than successful Capstone decoding. -/
def KernelInstruction.semantics? (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) : Option InstructionResult := do
  let decoded <- instruction.decode? pe
  executeInstruction pe imports instruction.rva 0 decoded initialSymbolic

def KernelInstruction.checked (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) : Bool :=
  instruction.semantics? pe imports |>.isSome

/-! FNSAVE/FRSTOR are protocol operations, not ordinary symbolic x86
instructions.  Keeping them in a separate checked node type prevents the
state-only symbolic decoder from silently treating physical x87 changes as a
no-op. -/

inductive KernelX87FrameOperation where
  | fnSave
  | frStor
deriving Repr, DecidableEq

structure KernelX87FrameDecoded where
  operation : KernelX87FrameOperation
  addressing : Addressing
  size : Nat
deriving Repr, DecidableEq

structure KernelX87FrameInstruction where
  rva : Nat
  bytes : Bytes
  operation : KernelX87FrameOperation
deriving Repr, DecidableEq

/-- An ordinary architectural x87 command in the native kernel.  It is kept
separate from symbolic integer blocks because its transition is checked by the
reviewed physical x87 model. -/
structure KernelX87CommandInstruction where
  rva : Nat
  bytes : Bytes
deriving Repr, DecidableEq

def kernelX87FrameBytes : Nat := 108

/-- Decode only unprefixed IA-32 FNSAVE (`DD /6`) and FRSTOR (`DD /4`) with a
32-bit memory operand.  Register forms, operand/address-size prefixes, FS/GS
overrides, and every other x87 opcode fail closed. -/
def decodeKernelX87FrameExact : Bytes -> Option KernelX87FrameDecoded
  | 0xdd :: tail => do
      let parsed <- parseModRM tail
      let addressing <- match parsed.operand with
        | .memory addressing => some addressing
        | .register _ | .immediate _ => none
      let operation <- match parsed.reg with
        | .esi => some .fnSave
        | .esp => some .frStor
        | _ => none
      some { operation, addressing, size := 1 + parsed.size }
  | _ => none

/-- Re-read and independently decode the submitted frame instruction from the
exact executable PE bytes. -/
def KernelX87FrameInstruction.decode? (pe : PE32)
    (instruction : KernelX87FrameInstruction) : Option KernelX87FrameDecoded := do
  if instruction.bytes.isEmpty || instruction.bytes.length > 15 then none else
  let exact <- spanBytes pe
    { start := instruction.rva, size := instruction.bytes.length }
  if exact != instruction.bytes then none else
  let fetched <- executableInstructionWindow pe instruction.rva
  let decoded <- decodeKernelX87FrameExact fetched
  if decoded.size != instruction.bytes.length ||
      fetched.take decoded.size != instruction.bytes ||
      decoded.operation != instruction.operation then none else
  some decoded

def KernelX87FrameInstruction.checked (pe : PE32)
    (instruction : KernelX87FrameInstruction) : Bool :=
  (instruction.decode? pe).isSome

def KernelX87FrameInstruction.successor
    (instruction : KernelX87FrameInstruction) : Nat :=
  instruction.rva + instruction.bytes.length

def KernelX87FrameInstruction.ownedRvas
    (instruction : KernelX87FrameInstruction) : List Nat :=
  (List.range instruction.bytes.length).map (instruction.rva + ·)

/-- Re-read and independently decode one complete x87 command from the exact
candidate image. -/
def KernelX87CommandInstruction.decode? (pe : PE32)
    (instruction : KernelX87CommandInstruction) :
    Option StageA.Relational.X87.DecodedCommand := do
  if instruction.bytes.isEmpty || instruction.bytes.length > 15 then none else
  let exact <- spanBytes pe
    { start := instruction.rva, size := instruction.bytes.length }
  if exact != instruction.bytes then none else
  let fetched <- executableInstructionWindow pe instruction.rva
  let decoded <- StageA.Relational.X87.decodeCommandExact fetched
  if decoded.size != instruction.bytes.length ||
      fetched.take decoded.size != instruction.bytes then none else
  some decoded

def KernelX87CommandInstruction.checked (pe : PE32)
    (instruction : KernelX87CommandInstruction) : Bool :=
  (instruction.decode? pe).isSome

def KernelX87CommandInstruction.successor
    (instruction : KernelX87CommandInstruction) : Nat :=
  instruction.rva + instruction.bytes.length

def KernelX87CommandInstruction.ownedRvas
    (instruction : KernelX87CommandInstruction) : List Nat :=
  (List.range instruction.bytes.length).map (instruction.rva + ·)

def decodeX87FrameNat (image : List (BitVec 8))
    (offset count : Nat) : Nat :=
  (List.range count).foldl (fun value index =>
    value + (image.getD (offset + index) (BitVec.ofNat 8 0)).toNat *
      2 ^ (8 * index)) 0

def writeX87FrameBytes : Memory -> Word -> List (BitVec 8) -> Memory
  | memory, _, [] => memory
  | memory, address, byte :: tail =>
      writeX87FrameBytes (Memory.write8 memory address byte)
        (address + BitVec.ofNat 32 1) tail

theorem writeX87FrameBytes_eq_of_outside
    (memory : Memory) (address query : Word) (bytes : List (BitVec 8))
    (outside : ∀ offset, offset < bytes.length ->
      query ≠ address + BitVec.ofNat 32 offset) :
    writeX87FrameBytes memory address bytes query = memory query := by
  induction bytes generalizing memory address with
  | nil => rfl
  | cons byte tail induction =>
      rw [writeX87FrameBytes]
      rw [induction]
      · have headOutside : query ≠ address := by
          simpa using outside 0 (by simp)
        unfold Memory.write8
        split
        · next equal =>
            exact False.elim (headOutside equal)
        · rfl
      · intro offset offsetBefore
        have tailOutside := outside (offset + 1) (by simp; omega)
        simpa [BitVec.add_assoc, ← BitVec.ofNat_add, Nat.add_comm] using
          tailOutside

theorem wordOffset_injective_of_fits
    (address : Word) (count left right : Nat)
    (fits : address.toNat + count <= 2 ^ 32)
    (leftBefore : left < count) (rightBefore : right < count)
    (equal :
      address + BitVec.ofNat 32 left =
        address + BitVec.ofNat 32 right) :
    left = right := by
  have leftWord : left < 2 ^ 32 := by omega
  have rightWord : right < 2 ^ 32 := by omega
  have leftSum : address.toNat + left < 2 ^ 32 := by omega
  have rightSum : address.toNat + right < 2 ^ 32 := by omega
  have equalNat := congrArg BitVec.toNat equal
  simp only [BitVec.toNat_add, BitVec.toNat_ofNat] at equalNat
  rw [Nat.mod_eq_of_lt leftWord, Nat.mod_eq_of_lt rightWord,
    Nat.mod_eq_of_lt leftSum, Nat.mod_eq_of_lt rightSum] at equalNat
  omega

theorem writeX87FrameBytes_getD
    (memory : Memory) (address : Word) (bytes : List (BitVec 8))
    (offset : Nat)
    (fits : address.toNat + bytes.length <= 2 ^ 32)
    (offsetBefore : offset < bytes.length) :
    writeX87FrameBytes memory address bytes
        (address + BitVec.ofNat 32 offset) =
      bytes.getD offset (BitVec.ofNat 8 0) := by
  induction bytes generalizing memory address offset with
  | nil => simp at offsetBefore
  | cons byte tail induction =>
      cases offset with
      | zero =>
          have tailPreserves :
              writeX87FrameBytes (Memory.write8 memory address byte)
                  (address + BitVec.ofNat 32 1) tail address =
                (Memory.write8 memory address byte) address := by
            apply writeX87FrameBytes_eq_of_outside
            intro tailOffset tailOffsetBefore overlap
            have offsetsEqual := wordOffset_injective_of_fits address
              (tail.length + 1) 0 (tailOffset + 1) (by simpa using fits)
              (by omega) (by omega) (by
                simpa [BitVec.add_assoc, ← BitVec.ofNat_add, Nat.add_comm] using
                  overlap)
            omega
          rw [writeX87FrameBytes]
          simpa [Memory.write8] using tailPreserves
      | succ tailOffset =>
          rw [writeX87FrameBytes]
          have tailOffsetBefore : tailOffset < tail.length := by
            simpa using offsetBefore
          have addressStep :
              (address + BitVec.ofNat 32 1).toNat = address.toNat + 1 := by
            rw [BitVec.toNat_add, BitVec.toNat_ofNat]
            simp only [Nat.one_mod]
            rw [Nat.mod_eq_of_lt]
            omega
          have tailFits :
              (address + BitVec.ofNat 32 1).toNat + tail.length <=
                2 ^ 32 := by
            calc
              (address + BitVec.ofNat 32 1).toNat + tail.length =
                  address.toNat + 1 + tail.length := by rw [addressStep]
              _ = address.toNat + (byte :: tail).length := by simp; omega
              _ <= 2 ^ 32 := fits
          simpa [BitVec.add_assoc, ← BitVec.ofNat_add, Nat.add_comm,
            List.getD] using
            induction (Memory.write8 memory address byte)
              (address + BitVec.ofNat 32 1) tailOffset tailFits
              tailOffsetBefore

theorem readBytes_writeX87FrameBytes
    (memory : Memory) (address : Word) (bytes : List (BitVec 8))
    (fits : address.toNat + bytes.length <= 2 ^ 32) :
    Engine.readBytes (writeX87FrameBytes memory address bytes)
      address bytes.length = bytes := by
  apply List.ext_get
  · simp [Engine.readBytes]
  · intro offset resultBefore bytesBefore
    have right :
        bytes.get ⟨offset, bytesBefore⟩ =
          bytes.getD offset (BitVec.ofNat 8 0) :=
      List.getElem_eq_getD (h := bytesBefore) (BitVec.ofNat 8 0)
    rw [right]
    simpa [Engine.readBytes] using
      writeX87FrameBytes_getD memory address bytes offset fits bytesBefore

def kernelX87PhysicalSlot (state : StageA.X87.PhysicalState)
    (index : Nat) : StageA.X87.Slot :=
  if bounded : index < 8 then state.slots.get ⟨index, bounded⟩ else .empty

def kernelX87SlotTag : StageA.X87.Slot -> Nat
  | .empty => 3
  | .occupied .valid _ => 0
  | .occupied .zero _ => 1
  | .occupied .special _ => 2

def kernelX87SlotValue : StageA.X87.Slot -> StageA.X87.Word
  | .empty => BitVec.ofNat 80 0
  | .occupied _ value => value

/-- Keep the older symbolic x87 projection coherent with the authoritative
physical state.  Logical ST(i) is derived through TOP; empty slots have no
architecturally observable payload in either model. -/
def kernelX87LegacyState (physical : StageA.X87.PhysicalState)
    (semantics : X87Semantics) : X87MachineState := {
  stack := fun index => kernelX87SlotValue (physical.logicalSlot index)
  control := physical.control
  status := physical.status
  semantics
}

def kernelX87TagWord (state : StageA.X87.PhysicalState) : Nat :=
  (List.range 8).foldl (fun tags index =>
    tags + kernelX87SlotTag (kernelX87PhysicalSlot state index) *
      2 ^ (2 * index)) 0

def kernelX87FrameZeroes (count : Nat) : List (BitVec 8) :=
  List.replicate count (BitVec.ofNat 8 0)

theorem kernelEncodeLittleEndian_length (count value : Nat) :
    (encodeLittleEndian count value).length = count := by
  simp [encodeLittleEndian]

/-- The flat-memory profile can model the complete x87 frame only when its
last byte remains in the 32-bit address space.  Segmentation and paging are
outside this profile; executions requiring either fault model remain
incomplete at the launch/environment boundary. -/
def kernelX87FrameAddressValid (address : Word) : Bool :=
  decide (address.toNat + kernelX87FrameBytes <= 2 ^ 32)

/-- Exact 108-byte protected-mode FNSAVE image.  Empty physical registers have
zero payload because the formal physical state intentionally carries no hidden
payload for an empty slot. -/
def encodeKernelX87Frame (state : StageA.X87.PhysicalState) : List (BitVec 8) :=
  encodeLittleEndian 2 state.control.toNat ++ kernelX87FrameZeroes 2 ++
  encodeLittleEndian 2 state.status.toNat ++ kernelX87FrameZeroes 2 ++
  encodeLittleEndian 2 (kernelX87TagWord state) ++ kernelX87FrameZeroes 2 ++
  encodeLittleEndian 4 state.instructionPointer.toNat ++
  encodeLittleEndian 2 state.codeSelector.toNat ++
  encodeLittleEndian 2 state.lastOpcode.toNat ++
  encodeLittleEndian 4 state.dataPointer.toNat ++
  encodeLittleEndian 2 state.dataSelector.toNat ++ kernelX87FrameZeroes 2 ++
  (List.range 8).flatMap fun index =>
    encodeLittleEndian 10
      (kernelX87SlotValue (kernelX87PhysicalSlot state index)).toNat

theorem encodeKernelX87Frame_length (state : StageA.X87.PhysicalState) :
    (encodeKernelX87Frame state).length = kernelX87FrameBytes := by
  simp only [encodeKernelX87Frame, List.length_append,
    kernelEncodeLittleEndian_length, kernelX87FrameZeroes,
    List.length_replicate, List.length_flatMap, List.length_range]
  rfl

def decodeKernelX87Tag (tag : Nat) : StageA.X87.Tag :=
  match tag % 4 with
  | 0 => .valid
  | 1 => .zero
  | _ => .special

def decodeKernelX87Slot (image : List (BitVec 8))
    (tagWord index : Nat) : StageA.X87.Slot :=
  let tag := (tagWord / 2 ^ (2 * index)) % 4
  if tag == 3 then .empty else
    .occupied (decodeKernelX87Tag tag)
      (BitVec.ofNat 80 (decodeX87FrameNat image (28 + 10 * index) 10))

/-- Decode exactly one 108-byte 32-bit protected-mode FSAVE image.  Reserved
bytes are read but intentionally ignored, matching architectural FRSTOR. -/
def decodeKernelX87Frame (image : List (BitVec 8)) :
    Option StageA.X87.PhysicalState :=
  if image.length != kernelX87FrameBytes then none else
  let status := decodeX87FrameNat image 4 2
  let tagWord := decodeX87FrameNat image 8 2
  some {
    slots := Vector.ofFn fun index =>
      decodeKernelX87Slot image tagWord index.val
    control := BitVec.ofNat 16 (decodeX87FrameNat image 0 2)
    status := BitVec.ofNat 16 status
    pendingException := (status / 2 ^ 7) % 2 == 1
    lastOpcode := BitVec.ofNat 11 (decodeX87FrameNat image 18 2)
    instructionPointer := BitVec.ofNat 32 (decodeX87FrameNat image 12 4)
    codeSelector := BitVec.ofNat 16 (decodeX87FrameNat image 16 2)
    dataPointer := BitVec.ofNat 32 (decodeX87FrameNat image 20 4)
    dataSelector := BitVec.ofNat 16 (decodeX87FrameNat image 24 2)
  }

def KernelX87PhysicalStateRepresentable
    (state : StageA.X87.PhysicalState) : Prop :=
  decodeKernelX87Frame (encodeKernelX87Frame state) = some state

def kernelX87FrameAddress (addressing : Addressing)
    (state : MachineState) : Word :=
  (addressing.expression initialSymbolic.registers).eval state

def executeKernelX87Frame? (decoded : KernelX87FrameDecoded)
    (state : MachineState) : Option MachineState := do
  let address := kernelX87FrameAddress decoded.addressing state
  if !kernelX87FrameAddressValid address then none else
  match decoded.operation with
  | .fnSave =>
      let reset := StageA.X87.initialPhysicalState
      some { state with
        memory := writeX87FrameBytes state.memory address
          (encodeKernelX87Frame state.x87Physical)
        x87 := kernelX87LegacyState reset state.x87.semantics
        x87Physical := reset }
  | .frStor => do
      let restored <- decodeKernelX87Frame
        (readBytes state.memory address kernelX87FrameBytes)
      some { state with
        x87 := kernelX87LegacyState restored state.x87.semantics
        x87Physical := restored }

/-- Physical frame save/restore cannot replace the parametric x87 semantics
implementation carried by the machine state. -/
theorem executeKernelX87Frame?_x87Semantics
    (decoded : KernelX87FrameDecoded) (state after : MachineState)
    (executed : executeKernelX87Frame? decoded state = some after) :
    after.x87Semantics = state.x87Semantics := by
  unfold executeKernelX87Frame? at executed
  simp only [Option.bind_eq_bind] at executed
  split at executed <;> try contradiction
  cases operationExact : decoded.operation with
  | fnSave =>
      simp only [operationExact] at executed
      injection executed with afterExact
      subst after
      rfl
  | frStor =>
      simp only [operationExact] at executed
      rw [Option.bind_eq_some_iff] at executed
      obtain ⟨restored, _restoredExact, executed⟩ := executed
      injection executed with afterExact
      subst after
      rfl

theorem executeKernelX87Frame?_frStor_of_encoded
    (addressing : Addressing) (size : Nat) (state : MachineState)
    (restored : StageA.X87.PhysicalState) (address : Word)
    (addressExact : kernelX87FrameAddress addressing state = address)
    (addressValid : kernelX87FrameAddressValid address = true)
    (encoded : readBytes state.memory address kernelX87FrameBytes =
      encodeKernelX87Frame restored)
    (representable : KernelX87PhysicalStateRepresentable restored) :
    ∃ after, executeKernelX87Frame?
        { operation := .frStor, addressing, size } state = some after ∧
      after.x87Physical = restored := by
  refine ⟨{ state with
    x87 := kernelX87LegacyState restored state.x87.semantics
    x87Physical := restored }, ?_, rfl⟩
  unfold executeKernelX87Frame?
  simp only [addressExact, addressValid, Bool.not_true, Bool.false_eq_true]
  rw [encoded, representable]
  rfl

theorem executeKernelX87Frame?_fnSave_encodes
    (addressing : Addressing) (size : Nat)
    (state : MachineState) (address : Word)
    (addressExact : kernelX87FrameAddress addressing state = address)
    (addressValid : kernelX87FrameAddressValid address = true) :
    ∃ after, executeKernelX87Frame?
        { operation := .fnSave, addressing, size } state = some after ∧
      readBytes after.memory address kernelX87FrameBytes =
        encodeKernelX87Frame state.x87Physical := by
  let after : MachineState := { state with
    memory := writeX87FrameBytes state.memory address
      (encodeKernelX87Frame state.x87Physical)
    x87 := kernelX87LegacyState StageA.X87.initialPhysicalState
      state.x87.semantics
    x87Physical := StageA.X87.initialPhysicalState }
  refine ⟨after, ?_, ?_⟩
  · simp [executeKernelX87Frame?, addressExact, addressValid, after]
  · have fits : address.toNat + kernelX87FrameBytes <= 2 ^ 32 := by
      simpa [kernelX87FrameAddressValid] using addressValid
    simpa [after, encodeKernelX87Frame_length] using
      readBytes_writeX87FrameBytes state.memory address
        (encodeKernelX87Frame state.x87Physical) (by
          simpa [encodeKernelX87Frame_length] using fits)

/-- Engine-relative protocol evidence used by operation proofs.  The static
checker establishes the exact frame operation; this proposition additionally
ties its 108-byte image to the checked semantic `EngineRep` at an ABI boundary. -/
def KernelX87FrameRelated (rep : EngineRep) (originalRva : Nat)
    (original candidate : MachineState) (frameAddress : Word) : Prop :=
  rep.Valid ∧
    (∀ entry ∈ rep.layout.fields,
      EngineFieldHolds rep original originalRva candidate.memory entry) ∧
    original.x87Semantics = rep.x87Semantics ∧
    candidate.x87Semantics = rep.x87Semantics ∧
    readBytes candidate.memory frameAddress kernelX87FrameBytes =
      encodeKernelX87Frame original.x87Physical

def outcomeStaticSuccessors : OutcomeExpr -> Option (List Nat)
  | .returned _ => some []
  | .jump target => some [target]
  | .branch _ taken fallthrough => some [taken, fallthrough]
  | .call target continuation _ => some [target, continuation]
  | .externalCall _ _ continuation => some [continuation]
  | .externalJump _ _ => some []
  | .bulkCopy _ continuation => some [continuation]
  | .bulkFill _ continuation => some [continuation]
  | .checkedContinue _ continuation => some [continuation]
  | .atomicCompareExchange _ _ _ continuation => some [continuation]
  /- The dynamic callee is checked by the callback-target inventory, but a
  returning indirect call still has an exact decoded continuation edge. -/
  | .indirectCall _ continuation _ => some [continuation]
  | .indirectJump _ => none

def KernelInstruction.staticSuccessors? (pe : PE32)
    (imports : List PEImport) (instruction : KernelInstruction) :
    Option (List Nat) := do
  let decoded <- instruction.decode? pe
  let result <- executeInstruction pe imports instruction.rva 0 decoded initialSymbolic
  match result with
  | .next _ => some [instruction.rva + decoded.size]
  | .stop behavior => do
      let outcome <- behavior.outcome
      outcomeStaticSuccessors outcome

structure KernelBlock where
  entryRva : Nat
  instructions : List KernelInstruction
  successors : List Nat
deriving Repr, DecidableEq

def KernelBlock.linearPrefixChecked (pe : PE32) (imports : List PEImport) :
    List KernelInstruction -> Bool
  | [] | [_] => true
  | instruction :: next :: tail =>
      match instruction.semantics? pe imports with
      | some (.next _) =>
          instruction.rva + instruction.bytes.length == next.rva &&
            KernelBlock.linearPrefixChecked pe imports (next :: tail)
      | _ => false

def KernelBlock.checked (pe : PE32) (imports : List PEImport)
    (block : KernelBlock) : Bool :=
  !block.instructions.isEmpty &&
    block.instructions.head?.map (·.rva) == some block.entryRva &&
    decide (block.instructions.map (·.rva)).Nodup &&
    block.instructions.all (·.checked pe imports) &&
    KernelBlock.linearPrefixChecked pe imports block.instructions &&
    match block.instructions.getLast? with
    | none => false
    | some last => last.staticSuccessors? pe imports == some block.successors

/-- Execute a submitted block symbolically while re-decoding every instruction
from the exact candidate PE.  This is stronger than checking each instruction
in isolation: unsupported state threading between two otherwise supported
instructions makes the whole block fail closed. -/
def runKernelBlockSymbolic (pe : PE32) (imports : List PEImport) :
    Nat -> SymbolicBehavior -> List KernelInstruction ->
      Option SymbolicBehavior
  | _, symbolic, [] => some symbolic
  | undefinedSlot, symbolic, instruction :: tail => do
      let decoded <- instruction.decode? pe
      let result <- executeInstruction pe imports instruction.rva undefinedSlot
        decoded symbolic
      match tail, result with
      | [], .next after | [], .stop after => some after
      | _ :: _, .next after =>
          runKernelBlockSymbolic pe imports (undefinedSlot + 1) after tail
      | _ :: _, .stop _ => none

def KernelBlock.symbolicBehavior? (pe : PE32) (imports : List PEImport)
    (block : KernelBlock) : Option SymbolicBehavior :=
  runKernelBlockSymbolic pe imports 0 initialSymbolic block.instructions

theorem KernelBlock.symbolicBehavior?_exact (pe : PE32)
    (imports : List PEImport) (block : KernelBlock)
    (behavior : SymbolicBehavior)
    (checked : block.symbolicBehavior? pe imports = some behavior) :
    runKernelBlockSymbolic pe imports 0 initialSymbolic block.instructions =
      some behavior :=
  checked

def runKernelBlockConcrete (pe : PE32) (imports : List PEImport) :
    Nat -> MachineState -> List KernelInstruction -> PE32InstructionExecution
  | undefinedSlot, state, [] => .running 0 undefinedSlot state
  | undefinedSlot, state, [instruction] =>
      stepPE32Instruction pe imports
        (.running instruction.rva undefinedSlot state)
  | undefinedSlot, state, instruction :: next :: tail =>
      match stepPE32Instruction pe imports
          (.running instruction.rva undefinedSlot state) with
      | .running nextRva nextSlot nextState =>
          if nextRva == next.rva then
            runKernelBlockConcrete pe imports nextSlot nextState (next :: tail)
          else .fault
      | .stopped outcome nextState => .stopped outcome nextState
      | .fault => .fault

def KernelBlock.symbolicConcreteAgree (block : KernelBlock)
    (behavior : SymbolicBehavior) (input : MachineState)
    (execution : PE32InstructionExecution) : Prop :=
  let concrete := behavior.eval input
  let expectedState := concreteBehaviorNextMachineState concrete input
  match concrete.outcome, execution with
  | none, .running nextRva nextSlot state =>
      block.instructions.getLast?.map (fun instruction =>
        instruction.rva + instruction.bytes.length) = some nextRva ∧
        nextSlot = block.instructions.length ∧ state = expectedState
  | some expected, .stopped observed state =>
      observed = expected ∧ state = expectedState
  | _, _ => False

/-- Central local soundness target.  Unlike successful symbolic evaluation,
this proposition states that expression composition agrees with actual exact-PE
instruction stepping for every concrete machine state. -/
def KernelBlock.SymbolicExecutionSound (pe : PE32) (imports : List PEImport)
    (block : KernelBlock) : Prop :=
  ∀ behavior,
    block.symbolicBehavior? pe imports = some behavior ->
    ∀ input,
      block.symbolicConcreteAgree behavior input
        (runKernelBlockConcrete pe imports 0 input block.instructions)

structure KernelLoop where
  headerRva : Nat
  latchRva : Nat
  bodyEntries : List Nat
deriving Repr, DecidableEq

def KernelLoop.checked (blocks : List KernelBlock) (loop : KernelLoop) : Bool :=
  !loop.bodyEntries.isEmpty && decide loop.bodyEntries.Nodup &&
    loop.bodyEntries.contains loop.headerRva &&
    loop.bodyEntries.contains loop.latchRva &&
    blocks.any fun block =>
      block.entryRva == loop.latchRva && block.successors.contains loop.headerRva

def framePush (decoded : DecodedInstruction) : Bool :=
  match decoded.instruction with
  | .pushReg .ebp => true
  | _ => false

def frameSetup (decoded : DecodedInstruction) : Bool :=
  match decoded.instruction with
  | .movRegReg .ebp .esp => true
  | _ => false

def frameLeave (decoded : DecodedInstruction) : Bool :=
  match decoded.instruction with
  | .leave | .popReg .ebp => true
  | _ => false

def frameReturn (decoded : DecodedInstruction) : Bool :=
  match decoded.instruction with
  | .ret | .retPop _ => true
  | _ => false

structure KernelFrameWitness where
  required : Bool
  pushRva : Nat
  setupRva : Nat
  teardownRvas : List Nat
  returnRvas : List Nat
deriving Repr, DecidableEq

inductive KernelRole where
  | programLookup
  | interpreterStep
  | runFunction
  | invokeCall
  | helper (id : Nat)
deriving Repr, DecidableEq

structure KernelFunction where
  role : KernelRole
  hint : String
  span : Span
  bytes : Bytes
  sha256 : String
  blocks : List KernelBlock
  x87Frames : List KernelX87FrameInstruction := []
  x87Commands : List KernelX87CommandInstruction := []
  padding : List Span
  loops : List KernelLoop
  frame : KernelFrameWitness
deriving Repr, DecidableEq

def KernelInstruction.ownedRvas (instruction : KernelInstruction) : List Nat :=
  (List.range instruction.bytes.length).map (instruction.rva + ·)

def KernelFunction.codeRvas (function : KernelFunction) : List Nat :=
  (function.blocks.flatMap fun block =>
    block.instructions.flatMap KernelInstruction.ownedRvas) ++
      function.x87Frames.flatMap KernelX87FrameInstruction.ownedRvas ++
      function.x87Commands.flatMap KernelX87CommandInstruction.ownedRvas

def KernelFunction.paddingRvas (function : KernelFunction) : List Nat :=
  function.padding.flatMap fun span =>
    (List.range span.size).map (span.start + ·)

def KernelFunction.ownedRvas (function : KernelFunction) : List Nat :=
  function.codeRvas ++ function.paddingRvas

def spanInside (inner outer : Span) : Bool :=
  outer.start <= inner.start && inner.stop <= outer.stop

def KernelFunction.instructions (function : KernelFunction) :
    List KernelInstruction :=
  function.blocks.flatMap (·.instructions)

def KernelFunction.instructionAt? (function : KernelFunction) (rva : Nat) :
    Option KernelInstruction :=
  function.instructions.find? (·.rva == rva)

def KernelFunction.decodedAt? (pe : PE32) (function : KernelFunction)
    (rva : Nat) : Option DecodedInstruction := do
  let instruction <- function.instructionAt? rva
  instruction.decode? pe

def KernelFunction.previousInstruction? (function : KernelFunction)
    (rva : Nat) : Option KernelInstruction :=
  function.instructions.find? fun instruction =>
    instruction.rva + instruction.bytes.length == rva

/-- `-O0 -fno-inline -fno-omit-frame-pointer` gives each checked C kernel
function a canonical EBP frame.  The witness is validated against decoded
instructions, not against symbol names or compiler flags. -/
def KernelFrameWitness.checked (pe : PE32) (function : KernelFunction)
    (frame : KernelFrameWitness) : Bool :=
  if !frame.required then true else
    frame.pushRva == function.span.start &&
    (function.decodedAt? pe frame.pushRva).any framePush &&
    (function.decodedAt? pe frame.setupRva).any frameSetup &&
    ((function.instructionAt? frame.pushRva).any fun push =>
      push.rva + push.bytes.length == frame.setupRva) &&
    !frame.returnRvas.isEmpty && decide frame.returnRvas.Nodup &&
    frame.teardownRvas.length == frame.returnRvas.length &&
    ((List.zip frame.teardownRvas frame.returnRvas).all fun pair =>
      pair.1 < pair.2 &&
        (function.decodedAt? pe pair.1).any frameLeave &&
        (function.decodedAt? pe pair.2).any frameReturn &&
        (function.blocks.any fun block =>
          block.instructions.any (·.rva == pair.1) &&
            block.instructions.any (·.rva == pair.2))) &&
    (function.instructions.all fun instruction =>
      match instruction.decode? pe with
      | some decoded => !frameReturn decoded || frame.returnRvas.contains instruction.rva
      | none => false)

def KernelFunction.checked (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) : Bool :=
  function.span.size == function.bytes.length &&
    spanBytes pe function.span == some function.bytes &&
    KernelSHA256.checkedHex function.bytes function.sha256 &&
    !(function.blocks.isEmpty && function.x87Frames.isEmpty &&
      function.x87Commands.isEmpty) &&
    decide (function.blocks.map (·.entryRva)).Nodup &&
    decide (function.x87Frames.map (·.rva)).Nodup &&
    decide (function.x87Commands.map (·.rva)).Nodup &&
    function.blocks.all (·.checked pe imports) &&
    function.x87Frames.all (·.checked pe) &&
    function.x87Commands.all (·.checked pe) &&
    function.blocks.all (fun block =>
      (block.symbolicBehavior? pe imports).isSome) &&
    function.blocks.all (fun block => block.instructions.all fun instruction =>
      spanInside { start := instruction.rva, size := instruction.bytes.length }
        function.span) &&
    function.x87Frames.all (fun instruction =>
      spanInside { start := instruction.rva, size := instruction.bytes.length }
        function.span) &&
    function.x87Commands.all (fun instruction =>
      spanInside { start := instruction.rva, size := instruction.bytes.length }
        function.span) &&
    function.padding.all (fun span =>
      spanInside span function.span &&
        (spanBytes pe span).any paddingBytes) &&
    decide function.ownedRvas.Nodup &&
    function.ownedRvas.length == function.span.size &&
    ((List.range function.span.size).all fun offset =>
      function.ownedRvas.contains (function.span.start + offset)) &&
    function.loops.all (KernelLoop.checked function.blocks) &&
    decide (function.loops.map (fun loop =>
      (loop.latchRva, loop.headerRva))).Nodup &&
    (function.blocks.flatMap (fun block =>
      block.successors.filterMap fun target =>
        if target <= block.entryRva &&
            function.blocks.any (fun candidate =>
              candidate.entryRva == target) then
          some (block.entryRva, target)
        else none)).all (fun edge =>
          function.loops.any fun loop =>
            loop.latchRva == edge.1 && loop.headerRva == edge.2) &&
    KernelFrameWitness.checked pe function function.frame

def KernelFunction.blockEntries (function : KernelFunction) : List Nat :=
  function.blocks.map (·.entryRva)

def KernelFunction.nodeEntries (function : KernelFunction) : List Nat :=
  function.blockEntries ++ function.x87Frames.map (·.rva) ++
    function.x87Commands.map (·.rva)

def KernelFunction.localSuccessors (function : KernelFunction)
    (entry : Nat) : List Nat :=
  match function.blocks.find? (fun block => block.entryRva == entry) with
  | some block => block.successors.filter function.nodeEntries.contains
  | none =>
      match function.x87Frames.find? (fun frame => frame.rva == entry) with
      | some frame =>
          [frame.successor].filter function.nodeEntries.contains
      | none =>
          match function.x87Commands.find? (fun command => command.rva == entry) with
          | some command =>
              [command.successor].filter function.nodeEntries.contains
          | none => []

def closeKernelEntries (function : KernelFunction) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := reached.flatMap function.localSuccessors
      closeKernelEntries function fuel (reached ++ next).eraseDups

def KernelFunction.reachableEntries (function : KernelFunction) : List Nat :=
  closeKernelEntries function function.nodeEntries.length [function.span.start]

def KernelFunction.cfgClosed (function : KernelFunction) : Bool :=
  function.nodeEntries.all function.reachableEntries.contains

def KernelRole.required : KernelRole -> Bool
  | .programLookup | .interpreterStep | .runFunction | .invokeCall => true
  | .helper _ => false

def requiredKernelRoles : List KernelRole :=
  [.programLookup, .interpreterStep, .runFunction, .invokeCall]

def executableRva (pe : PE32) (rva : Nat) : Bool :=
  pe.sections.any fun sec =>
    sec.executable && sec.virtualAddress <= rva &&
      rva < sec.virtualAddress + sec.mappedSize

structure CompiledKernelProgram where
  functions : List KernelFunction
deriving Repr, DecidableEq

def CompiledKernelProgram.blockEntries (program : CompiledKernelProgram) :
    List Nat :=
  program.functions.flatMap KernelFunction.blockEntries

def CompiledKernelProgram.nodeEntries (program : CompiledKernelProgram) :
    List Nat :=
  program.functions.flatMap KernelFunction.nodeEntries

def CompiledKernelProgram.rolePresentExactlyOnce
    (program : CompiledKernelProgram) (role : KernelRole) : Bool :=
  (program.functions.filter fun function => function.role == role).length == 1

def CompiledKernelProgram.functionEntry? (program : CompiledKernelProgram)
    (role : KernelRole) : Option Nat :=
  (program.functions.find? fun function => function.role == role).map
    (fun function => function.span.start)

def CompiledKernelProgram.directTargetsClosed (program : CompiledKernelProgram)
    (pe : PE32) : Bool :=
  program.functions.all fun function =>
    (function.blocks.all fun block =>
      block.successors.all fun target =>
        !executableRva pe target || program.nodeEntries.contains target) &&
    (function.x87Frames.all fun frame =>
      !executableRva pe frame.successor ||
        program.nodeEntries.contains frame.successor) &&
    (function.x87Commands.all fun command =>
      !executableRva pe command.successor ||
        program.nodeEntries.contains command.successor)

def closeKernelProgramEntries (program : CompiledKernelProgram) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := program.functions.flatMap fun function =>
        function.nodeEntries.flatMap fun entry =>
          if reached.contains entry then
            function.localSuccessors entry
          else []
      closeKernelProgramEntries program fuel (reached ++ next).eraseDups

def CompiledKernelProgram.rootEntries? (program : CompiledKernelProgram) :
    Option (List Nat) :=
  requiredKernelRoles.mapM program.functionEntry?

def CompiledKernelProgram.reachableEntries? (program : CompiledKernelProgram) :
    Option (List Nat) := do
  let roots <- program.rootEntries?
  some (closeKernelProgramEntries program program.nodeEntries.length roots)

/-- A closed rooted native kernel graph.  Linker symbols only propose roles;
this checker re-decodes every instruction, checks exact block successors,
requires every back-edge to have an explicit loop witness, and derives the
reachable closure from the four required operation roots. -/
def CompiledKernelProgram.checked (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport) : Bool :=
  !program.functions.isEmpty &&
    decide (program.functions.map (·.role)).Nodup &&
    decide program.nodeEntries.Nodup &&
    requiredKernelRoles.all program.rolePresentExactlyOnce &&
    program.functions.all (fun function =>
      function.checked pe imports && function.cfgClosed) &&
    program.directTargetsClosed pe &&
    match program.reachableEntries? with
    | none => false
    | some reached => program.nodeEntries.all reached.contains

/-! Exact native execution.  Ordinary instructions remain delegated to
`stepPE32Instruction`.  Only when that reviewed decoder faults do we try the
separate exact FNSAVE/FRSTOR frame decoder above.  The first profile leaves
indirect control as an explicit frontier rather than guessing whether a
function pointer is internal or an external runtime callback. -/

def stepKernelX87Frame? (pe : PE32) (rva undefinedSlot : Nat)
    (state : MachineState) : Option PE32InstructionExecution := do
  let fetched <- executableInstructionWindow pe rva
  let decoded <- decodeKernelX87FrameExact fetched
  let nextState <- executeKernelX87Frame? decoded state
  some (.running (rva + decoded.size) (undefinedSlot + 1)
    nextState)

/-- The executable-image decoder and concrete 108-byte transition are the
complete authority for a native x87 frame step.  This theorem is deliberately
definitional so generated certificates cannot substitute a solver result or a
status field for either operation. -/
theorem stepKernelX87Frame?_exact (pe : PE32) (rva undefinedSlot : Nat)
    (state : MachineState) :
    stepKernelX87Frame? pe rva undefinedSlot state = (do
      let fetched <- executableInstructionWindow pe rva
      let decoded <- decodeKernelX87FrameExact fetched
      let nextState <- executeKernelX87Frame? decoded state
      pure (.running (rva + decoded.size) (undefinedSlot + 1) nextState)) := by
  rfl

/-- Execute one ordinary architectural x87 command from the exact candidate
bytes.  Architectural x87 faults remain fail-closed in this native profile;
successful commands use the same reviewed physical-state semantics as the
original x87 schedules. -/
def executeKernelX87Command? (pe : PE32) (rva undefinedSlot : Nat)
    (state : MachineState) (descriptor : StageA.Relational.X87.DecodedCommand) :
    Option PE32InstructionExecution := do
  let input := StageA.Relational.X87.commandStepInput pe rva descriptor state
  if !input.checkedFor descriptor.command then none else
  if !descriptor.command.waitModeChecked descriptor.waitMode then none else
  let response := state.x87Semantics.execute descriptor.command descriptor.waitMode
    state.x87Physical input
  if !response.checkedFor descriptor.command descriptor.waitMode ||
      response.fault.isSome then none else
  let memoryAddress <- match response.store with
    | none => some none
    | some _ => (StageA.Relational.X87.commandDataAddress descriptor state).map some
  let behavior := StageA.Relational.X87.singletonBehavior state response
    memoryAddress (rva + descriptor.size)
  some (.running (rva + descriptor.size) (undefinedSlot + 1)
    (behavior.nextMachineState state))

/-- A successful architectural x87 command updates the physical response,
memory/register outputs, and flags but retains the semantics implementation
that produced that response. -/
theorem executeKernelX87Command?_running_x87Semantics
    (pe : PE32) (rva undefinedSlot nextRva nextSlot : Nat)
    (state after : MachineState)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (executed : executeKernelX87Command? pe rva undefinedSlot state descriptor =
      some (.running nextRva nextSlot after)) :
    after.x87Semantics = state.x87Semantics := by
  unfold executeKernelX87Command? at executed
  simp only [Option.bind_eq_bind] at executed
  split at executed <;> try contradiction
  split at executed <;> try contradiction
  split at executed <;> try contradiction
  split at executed <;> try contradiction
  all_goals
    rw [Option.bind_eq_some_iff] at executed
    obtain ⟨memoryAddress, _memoryAddressExact, executed⟩ := executed
    simp only [Option.some.injEq,
      PE32InstructionExecution.running.injEq] at executed
    rcases executed with ⟨_nextRva, _nextSlot, afterExact⟩
    subst after
    rfl

/-- Fetch and execute one exact ordinary x87 command.  Callers that have already
classified the fetched bytes should use `executeKernelX87Command?` so a semantic
failure cannot be confused with a decoder miss. -/
def stepKernelX87Command? (pe : PE32) (rva undefinedSlot : Nat)
    (state : MachineState) : Option PE32InstructionExecution := do
  let fetched <- executableInstructionWindow pe rva
  let descriptor <- StageA.Relational.X87.decodeCommandExact fetched
  executeKernelX87Command? pe rva undefinedSlot state descriptor

/-- Execute one exact candidate-kernel instruction.  A byte sequence decoded as
an x87 frame operation cannot fall back to the ordinary decoder when its
108-byte memory access is invalid. -/
def stepKernelPE32Instruction (pe : PE32) (imports : List PEImport) :
    PE32InstructionExecution -> PE32InstructionExecution
  | execution@(.running rva undefinedSlot state) =>
      match executableInstructionWindow pe rva with
      | some fetched =>
          match decodeKernelX87FrameExact fetched with
          | some decoded =>
              match executeKernelX87Frame? decoded state with
              | some nextState =>
                  .running (rva + decoded.size) (undefinedSlot + 1) nextState
              | none => .fault
          | none =>
              match StageA.Relational.X87.decodeCommandExact fetched with
              | some descriptor =>
                  match executeKernelX87Command? pe rva undefinedSlot state
                      descriptor with
                  | some next => next
                  | none => .fault
              | none => stepPE32Instruction pe imports execution
      | none => .fault
  | terminal => terminal

structure NativeCallFrame where
  continuationRva : Nat
  returnAddress : Word
deriving Repr, DecidableEq

structure NativeExternalEvent where
  imported : PEImport
  arguments : List Word
  state : MachineState

structure NativeEnvironment where
  result : Nat -> NativeExternalEvent -> MachineState

inductive NativeExecution where
  | running (rva undefinedSlot : Nat) (state : MachineState)
      (calls : List NativeCallFrame) (eventIndex : Nat)
      (events : List NativeExternalEvent)
  | returned (state : MachineState) (events : List NativeExternalEvent)
  | fault
  | unsupportedIndirect (rva : Nat) (target : Word)

def nextNativeExecution (environment : NativeEnvironment)
    (execution : NativeExecution) (outcome : ConcreteOutcome)
    (state : MachineState) (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) : NativeExecution :=
  match outcome with
  | .returned target =>
      match calls with
      | [] => .returned state events
      | frame :: tail =>
          if target == frame.returnAddress then
            .running frame.continuationRva 0 state tail eventIndex events
          else .fault
  | .jump target => .running target 0 state calls eventIndex events
  | .branch condition taken fallthrough =>
      .running (if condition then taken else fallthrough) 0 state calls
        eventIndex events
  | .call target continuation returnAddress =>
      .running target 0 state
        ({ continuationRva := continuation,
           returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
        eventIndex events
  | .externalCall imported arguments continuation =>
      let event := { imported, arguments, state }
      .running continuation 0 (environment.result eventIndex event) calls
        (eventIndex + 1) (events ++ [event])
  | .externalJump imported arguments =>
      let event := { imported, arguments, state }
      let result := environment.result eventIndex event
      match calls with
      | [] => .returned result (events ++ [event])
      | frame :: tail => .running frame.continuationRva 0 result tail
          (eventIndex + 1) (events ++ [event])
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction
        count.toNat
      .running continuation 0 { state with memory } calls eventIndex events
  | .bulkFill destination value count direction continuation =>
      let memory := Memory.bulkFillDwords state.memory destination value direction
        count.toNat
      .running continuation 0 { state with memory } calls eventIndex events
  | .checkedContinue valid continuation =>
      if valid then .running continuation 0 state calls eventIndex events else .fault
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected replacement
      .running continuation 0 { state with memory } calls eventIndex events
  | .indirectCall target _ _ | .indirectJump target =>
      .unsupportedIndirect executionRva target
  where
    executionRva := match execution with
      | .running rva _ _ _ _ _ => rva
      | _ => 0

def stepNativeExecution (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) : NativeExecution -> NativeExecution
  | execution@(.running rva undefinedSlot state calls eventIndex events) =>
      match stepKernelPE32Instruction pe imports
          (.running rva undefinedSlot state) with
      | .running nextRva nextSlot nextState =>
          .running nextRva nextSlot nextState calls eventIndex events
      | .stopped outcome nextState =>
          nextNativeExecution environment execution outcome nextState calls
            eventIndex events
      | .fault => .fault
  | terminal => terminal

inductive NativeSteps (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) : NativeExecution -> NativeExecution -> Prop
  | refl (state) : NativeSteps pe imports environment state state
  | tail (before middle after) :
      stepNativeExecution pe imports environment before = middle ->
      NativeSteps pe imports environment middle after ->
      NativeSteps pe imports environment before after

theorem NativeSteps.single (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (before : NativeExecution) :
    NativeSteps pe imports environment before
      (stepNativeExecution pe imports environment before) := by
  apply NativeSteps.tail before
    (stepNativeExecution pe imports environment before)
    (stepNativeExecution pe imports environment before) rfl
  exact NativeSteps.refl _

theorem NativeSteps.trans {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {left middle right : NativeExecution}
    (first : NativeSteps pe imports environment left middle)
    (second : NativeSteps pe imports environment middle right) :
    NativeSteps pe imports environment left right := by
  induction first with
  | refl => exact second
  | tail before next after stepped _ induction =>
      exact NativeSteps.tail before next right stepped (induction second)

def NativeDispatches (pe : PE32) (imports : List PEImport)
    (environment : NativeEnvironment) (entryRva : Nat)
    (before after : MachineState) (events : List NativeExternalEvent) : Prop :=
  NativeSteps pe imports environment
    (.running entryRva 0 before [] 0 []) (.returned after events)

/-! Footprint framing. -/

abbrev CandidateFootprint := Word -> Prop

def CandidateFootprintsDisjoint
    (left right : CandidateFootprint) : Prop :=
  ∀ address, left address -> ¬ right address

theorem CandidateFootprintsDisjoint.symm
    {left right : CandidateFootprint}
    (disjoint : CandidateFootprintsDisjoint left right) :
    CandidateFootprintsDisjoint right left := by
  intro address rightMember leftMember
  exact disjoint address leftMember rightMember

def MemoryAgreesOutside (footprint : CandidateFootprint)
    (after before : Memory) : Prop :=
  ∀ address, ¬ footprint address -> after address = before address

theorem MemoryAgreesOutside.refl (footprint : CandidateFootprint)
    (memory : Memory) : MemoryAgreesOutside footprint memory memory := by
  intro _ _
  rfl

theorem MemoryAgreesOutside.trans {footprint : CandidateFootprint}
    {first second third : Memory}
    (left : MemoryAgreesOutside footprint second first)
    (right : MemoryAgreesOutside footprint third second) :
    MemoryAgreesOutside footprint third first := by
  intro address outside
  exact (right address outside).trans (left address outside)

theorem MemoryAgreesOutside.write32Inside
    (footprint : CandidateFootprint) (beforeMemory : Memory)
    (writeAddress value : Word)
    (inside : ∀ byte, byte < 4 →
      footprint (writeAddress + BitVec.ofNat 32 byte)) :
    MemoryAgreesOutside footprint
      (beforeMemory.write32 writeAddress value) beforeMemory := by
  intro query outside
  unfold Memory.write32
  by_cases byte0 : query = writeAddress
  · exfalso
    apply outside
    simpa [byte0] using inside 0 (by omega)
  rw [if_neg byte0]
  by_cases byte1 : query = writeAddress + BitVec.ofNat 32 1
  · exfalso
    exact outside (byte1 ▸ inside 1 (by omega))
  rw [if_neg byte1]
  by_cases byte2 : query = writeAddress + BitVec.ofNat 32 2
  · exfalso
    exact outside (byte2 ▸ inside 2 (by omega))
  rw [if_neg byte2]
  by_cases byte3 : query = writeAddress + BitVec.ofNat 32 3
  · exfalso
    exact outside (byte3 ▸ inside 3 (by omega))
  rw [if_neg byte3]

theorem MemoryAgreesOutside.writeX87FrameInside
    (footprint : CandidateFootprint) (beforeMemory : Memory)
    (writeAddress : Word) (bytes : List (BitVec 8))
    (inside : ∀ offset, offset < bytes.length →
      footprint (writeAddress + BitVec.ofNat 32 offset)) :
    MemoryAgreesOutside footprint
      (writeX87FrameBytes beforeMemory writeAddress bytes) beforeMemory := by
  intro query outside
  apply writeX87FrameBytes_eq_of_outside
  intro offset offsetBefore equal
  exact outside (equal ▸ inside offset offsetBefore)

def FootprintDisjointFromRepresentation (rep : EngineRep)
    (footprint : CandidateFootprint) : Prop :=
  ∀ address, footprint address -> ¬ CandidateAddressObserved rep address

theorem candidateMemoryAgreesOnRepresentation_of_frame
    {rep : EngineRep} {footprint : CandidateFootprint}
    {after before : Memory}
    (frame : MemoryAgreesOutside footprint after before)
    (disjoint : FootprintDisjointFromRepresentation rep footprint) :
    CandidateMemoryAgreesOnRepresentation rep after before := by
  intro address observed
  apply frame address
  intro inside
  exact disjoint address inside observed

theorem StateRelated.preserve_framed_scratch {CandidateControl : Type}
    {rep : EngineRep} {controlRelated : Nat -> CandidateControl -> Prop}
    {originalRva : Nat} {candidateControl : CandidateControl}
    {original candidateBefore candidateAfter : MachineState}
    {footprint : CandidateFootprint}
    (related : StateRelated rep controlRelated originalRva candidateControl
      original candidateBefore)
    (frame : MemoryAgreesOutside footprint candidateAfter.memory
      candidateBefore.memory)
    (disjoint : FootprintDisjointFromRepresentation rep footprint)
    (semantics : candidateAfter.x87Semantics = candidateBefore.x87Semantics) :
    StateRelated rep controlRelated originalRva candidateControl
      original candidateAfter :=
  related.preserve_candidate_scratch
    (candidateMemoryAgreesOnRepresentation_of_frame frame disjoint) semantics

/-! Abstract operation model.  The fixed native kernel has four public
operations.  Their specifications below are concrete Lean definitions over
`ProgramRecord`; generated code is not allowed to replace them with a caller-
chosen postcondition or a Python status field. -/

inductive KernelOperation where
  | programLookup | interpreterStep | runFunction | invokeCall
deriving Repr, DecidableEq

def KernelOperation.role : KernelOperation -> KernelRole
  | .programLookup => .programLookup
  | .interpreterStep => .interpreterStep
  | .runFunction => .runFunction
  | .invokeCall => .invokeCall

def lookupProgramRecord (records : List ProgramRecord)
    (sourceRva : Nat) : Option ProgramRecord :=
  records.find? (fun record => record.sourceRva == sourceRva)

def abstractInterpreterStep (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (state : InterpreterMachine) : Option MacroResult := do
  let record <- lookupProgramRecord records sourceRva
  record.interpret environment state

/-! `abstractInterpreterStep` is retained as the executable, external-call-only
reference evaluator.  It is not the authoritative semantics for the recursive
kernel operations: internal and indirect calls are interpreted by the
call-aware relations below. -/

def abstractInterpreterInitialRuntime
    (state : InterpreterMachine) : RuntimeState := {
  input := state
  current := state
  callOutput := state
  words := fun _ => none
  events := []
}

def abstractInterpreterCallRuntime (runtime : RuntimeState)
    (event : CallEvent) (result : CallResult) : RuntimeState := {
  runtime with
  current := result.state
  callOutput := result.state
  events := runtime.events ++ [.call event]
}

def abstractInterpreterCallOutcome (runtime : RuntimeState)
    (event : CallEvent) (result : CallResult) :
    Option (Sum MacroResult RuntimeState) :=
  let next := abstractInterpreterCallRuntime runtime event result
  match result.status with
  | .ok => some (.inr next)
  | .divideError => some (.inl (halted next .divideError))
  | .memoryFault => some (.inl (halted next .memoryFault))
  | .externalFault => some (.inl (halted next .externalFault))
  | .unimplemented => some (.inl (halted next .unimplemented))

def abstractInterpreterTransferOutcome (outcome : SemanticOutcome) :
    Option (Sum MacroResult RuntimeState) -> Option MacroResult
  | none => none
  | some (.inl result) => some result
  | some (.inr runtime) => outcome.complete runtime

def completionContinuation? (resolveCodeTarget : Word -> Option Nat) :
    Completion -> Option Nat
  | .fallthrough target | .jump target | .branch target => some target
  | .indirectJump target => resolveCodeTarget target
  | _ => none

def completionCallStatus? : Completion -> Option CallStatus
  | .returned _ | .externalJump => some .ok
  | .divideError => some .divideError
  | .memoryFault => some .memoryFault
  | .externalFault => some .externalFault
  | .unimplemented => some .unimplemented
  | _ => none

mutual
  /-- Authoritative call-aware semantics for one interpreter Step.  The
  executable evaluator above cannot own internal calls because their result is
  the nested Run result, not an arbitrary external-environment result. -/
  inductive AbstractInterpreterStepDerivation
      (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      Nat -> InterpreterMachine -> Option MacroResult -> Prop
    | lookupUnavailable (sourceRva state)
        (lookupExact : lookupProgramRecord records sourceRva = none) :
        AbstractInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state none
    | decodeUnavailable (sourceRva state record)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = none) :
        AbstractInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state none
    | unchecked (sourceRva state record transfer)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = false) :
        AbstractInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state none
    | execute (sourceRva state record transfer result)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = true)
        (execution : AbstractSemanticTransferDerivation records environment
          resolveCodeTarget transfer state result) :
        AbstractInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state result

  inductive AbstractSemanticTransferDerivation
      (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      SemanticTransfer -> InterpreterMachine -> Option MacroResult -> Prop
    | execute (transfer state bodyResult)
        (body : AbstractInterpreterBodyDerivation records environment
          resolveCodeTarget transfer (abstractInterpreterInitialRuntime state)
          transfer.body bodyResult) :
        AbstractSemanticTransferDerivation records environment resolveCodeTarget
          transfer state
          (abstractInterpreterTransferOutcome transfer.outcome bodyResult)

  inductive AbstractInterpreterBodyDerivation
      (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> List SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | done (runtime) :
        AbstractInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime [] (some (.inr runtime))
    | actionUnavailable (runtime action tail)
        (head : AbstractInterpreterActionDerivation records environment
          resolveCodeTarget transfer runtime action none) :
        AbstractInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime (action :: tail) none
    | actionHalted (runtime action tail result)
        (head : AbstractInterpreterActionDerivation records environment
          resolveCodeTarget transfer runtime action (some (.inl result))) :
        AbstractInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime (action :: tail) (some (.inl result))
    | actionNext (runtime action tail next result)
        (head : AbstractInterpreterActionDerivation records environment
          resolveCodeTarget transfer runtime action (some (.inr next)))
        (rest : AbstractInterpreterBodyDerivation records environment
          resolveCodeTarget transfer next tail result) :
        AbstractInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime (action :: tail) result

  inductive AbstractInterpreterActionDerivation
      (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | nonCall (runtime action result)
        (notCall : ∀ callIndex, action != .call callIndex)
        (resultExact :
          transfer.executeAction environment runtime action = result) :
        AbstractInterpreterActionDerivation records environment resolveCodeTarget
          transfer runtime action result
    | call (runtime callIndex result)
        (edge : AbstractInterpreterCallTraceEdge records environment
          resolveCodeTarget transfer runtime callIndex result) :
        AbstractInterpreterActionDerivation records environment resolveCodeTarget
          transfer runtime (.call callIndex) result

  inductive AbstractInterpreterCallTraceEdge
      (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> Nat ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | invoke (runtime callIndex call event input result)
        (callExact : transfer.calls[callIndex]? = some call)
        (eventExact : call.event runtime = some (event, input))
        (invocation : AbstractInvokeCallDerivation records environment
          resolveCodeTarget event input result) :
        AbstractInterpreterCallTraceEdge records environment resolveCodeTarget
          transfer runtime callIndex
          (abstractInterpreterCallOutcome runtime event result)

  /-- Finite derivations are the semantics of `stage_b_run_function`.  An
  infinite internal loop has no terminating derivation, matching partial
  correctness; termination correspondence remains a whole-program obligation. -/
  inductive AbstractRunFunction (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      Nat -> InterpreterMachine -> CallResult -> Prop
    | unavailable (sourceRva state)
        (step : AbstractInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state none) :
        AbstractRunFunction records environment resolveCodeTarget sourceRva state
          { status := .unimplemented, state := state }
    | terminal (sourceRva state result status)
        (step : AbstractInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state (some result))
        (statusExact : completionCallStatus? result.completion = some status) :
        AbstractRunFunction records environment resolveCodeTarget sourceRva state
          { status := status, state := result.state }
    | next (sourceRva state result continuation final)
        (step : AbstractInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state (some result))
        (continuationExact :
          completionContinuation? resolveCodeTarget result.completion =
            some continuation)
        (rest : AbstractRunFunction records environment resolveCodeTarget
          continuation result.state final) :
        AbstractRunFunction records environment resolveCodeTarget sourceRva state
          final

  /-- External calls alone are delegated to `environment.invokeCall`.
  Internal and indirect calls execute a nested semantic Run. -/
  inductive AbstractInvokeCallDerivation (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat) :
      CallEvent -> InterpreterMachine -> CallResult -> Prop
    | external (event state)
        (kindExact : event.kind = .external) :
        AbstractInvokeCallDerivation records environment resolveCodeTarget event
          state (environment.invokeCall event state)
    | internal (event state result)
        (kindExact : event.kind = .internal)
        (run : AbstractRunFunction records environment resolveCodeTarget
          event.targetRva.toNat state result) :
        AbstractInvokeCallDerivation records environment resolveCodeTarget event
          state result
    | indirect (event state target result)
        (kindExact : event.kind = .indirect)
        (targetExact : resolveCodeTarget event.targetRva = some target)
        (run : AbstractRunFunction records environment resolveCodeTarget
          target state result) :
        AbstractInvokeCallDerivation records environment resolveCodeTarget event
          state result
end

inductive AbstractKernelRequest where
  | programLookup (records : List ProgramRecord) (sourceRva : Nat)
  | interpreterStep (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (sourceRva : Nat) (state : InterpreterMachine)
  | runFunction (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat)
      (sourceRva : Nat) (state : InterpreterMachine)
  | invokeCall (records : List ProgramRecord)
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat)
      (event : CallEvent) (state : InterpreterMachine)

def AbstractKernelRequest.operation : AbstractKernelRequest -> KernelOperation
  | .programLookup .. => .programLookup
  | .interpreterStep .. => .interpreterStep
  | .runFunction .. => .runFunction
  | .invokeCall .. => .invokeCall

inductive AbstractKernelResponse where
  | programLookup (record : Option ProgramRecord)
  | interpreterStep (result : Option MacroResult)
  | call (result : CallResult)

/-- This is the authoritative high-level behavior of the four exported
kernel functions. -/
inductive AbstractKernelTransition :
    AbstractKernelRequest -> AbstractKernelResponse -> Prop
  | programLookup (records sourceRva) :
      AbstractKernelTransition (.programLookup records sourceRva)
        (.programLookup (lookupProgramRecord records sourceRva))
  | interpreterStep (records environment resolveCodeTarget sourceRva state result) :
      AbstractInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result ->
      AbstractKernelTransition
        (.interpreterStep records environment sourceRva state)
        (.interpreterStep result)
  | runFunction (records environment resolveCodeTarget sourceRva state result) :
      AbstractRunFunction records environment resolveCodeTarget sourceRva state
        result ->
      AbstractKernelTransition
        (.runFunction records environment resolveCodeTarget sourceRva state)
        (.call result)
  | invokeExternal (records environment resolveCodeTarget event state) :
      event.kind = .external ->
      AbstractKernelTransition
        (.invokeCall records environment resolveCodeTarget event state)
        (.call (environment.invokeCall event state))
  | invokeInternal (records environment resolveCodeTarget event state result) :
      event.kind = .internal ->
      AbstractRunFunction records environment resolveCodeTarget event.targetRva.toNat
        state result ->
      AbstractKernelTransition
        (.invokeCall records environment resolveCodeTarget event state)
        (.call result)
  | invokeIndirect (records environment resolveCodeTarget event state target result) :
      event.kind = .indirect ->
      resolveCodeTarget event.targetRva = some target ->
      AbstractRunFunction records environment resolveCodeTarget target state result ->
      AbstractKernelTransition
        (.invokeCall records environment resolveCodeTarget event state)
        (.call result)

def interpreterRegister (register : Reg) : Register :=
  match register with
  | .eax => .eax | .ebx => .ebx | .ecx => .ecx | .edx => .edx
  | .esi => .esi | .edi => .edi | .ebp => .ebp | .esp => .esp

/-- The abstract interpreter state is exactly the architectural projection of
a formal x86 state.  Physical x87 state remains governed by `EngineRep`. -/
def InterpreterMachineMatches (logical : InterpreterMachine)
    (formal : MachineState) : Prop :=
  (∀ register, logical.registers (interpreterRegister register) =
    formal.registers.get register) ∧
  logical.memory = formal.memory ∧ logical.eflags = formal.eflags ∧
  (∀ flag, logical.flags flag =
    BitVec.zeroExtend 32
      (formal.eflags.extractLsb' flag.eflagsBit 1))

def DispatchInputRelated {CandidateControl : Type}
    (rep : EngineRep) (controlRelated : Nat -> CandidateControl -> Prop)
    (sourceRva : Nat) (candidateControl : CandidateControl)
    (logical : InterpreterMachine) (candidate : MachineState) : Prop :=
  ∃ formal,
    InterpreterMachineMatches logical formal ∧
    StateRelated rep controlRelated sourceRva candidateControl formal candidate

def DispatchOutputRelated {CandidateControl : Type}
    (rep : EngineRep) (controlRelated : Nat -> CandidateControl -> Prop)
    (resultControl : MacroResult -> Nat -> CandidateControl -> Prop)
    (result : MacroResult) (candidateControl : CandidateControl)
    (candidate : MachineState) : Prop :=
  ∃ formal resultRva,
    InterpreterMachineMatches result.state formal ∧
    StateRelated rep controlRelated resultRva candidateControl formal candidate ∧
    resultControl result resultRva candidateControl

/-- ABI correspondence is intentionally separate from operation semantics.
It may relate different concrete stack, state, and table addresses, but cannot
change what any abstract operation does.  Stage A's engine-layout proof must
construct this relation for the candidate. -/
structure KernelABIRelation where
  requestRelated : AbstractKernelRequest -> MachineState -> Prop
  responseRelated : AbstractKernelRequest -> AbstractKernelResponse ->
    MachineState -> List NativeExternalEvent -> Prop
  scratchFootprint : AbstractKernelRequest -> CandidateFootprint

/-- A dispatch relation accepted by the kernel operation theorem.  This is a
proof interface, not generated authority: each specialization must supply a
concrete execution relation whose constructors justify every dispatch. -/
abbrev KernelDispatchRelation :=
  Nat -> MachineState -> MachineState -> List NativeExternalEvent -> Prop

/-- Generic operation refinement over a concrete dispatch semantics.  Keeping
the operation theorem independent of one executor permits conservative
extensions, such as checked callback dispatch, without weakening or changing
the base native executor. -/
def KernelOperationRefinesUsing (program : CompiledKernelProgram)
    (abi : KernelABIRelation) (dispatches : KernelDispatchRelation)
    (operation : KernelOperation) : Prop :=
  ∀ request before,
    request.operation = operation -> abi.requestRelated request before ->
    ∀ response, AbstractKernelTransition request response ->
      ∃ entryRva after nativeEvents,
        program.functionEntry? operation.role = some entryRva ∧
        dispatches entryRva before after nativeEvents ∧
        abi.responseRelated request response after nativeEvents ∧
        MemoryAgreesOutside (abi.scratchFootprint request) after.memory before.memory

/-- The original fail-closed native specialization.  In particular,
`stepNativeExecution` still reports `unsupportedIndirect`; callback-aware
execution uses a separate checked specialization rather than altering this
definition. -/
def KernelOperationRefines (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport)
    (nativeEnvironment : NativeEnvironment) (abi : KernelABIRelation)
    (operation : KernelOperation) : Prop :=
  KernelOperationRefinesUsing program abi
    (NativeDispatches pe imports nativeEnvironment) operation

/-- The compiled-kernel theorem target.  The structural field is a reflected
checker over exact PE bytes.  `operations` is not generated data: it is the
four Lean simulation theorems that the kernel proof graph must build from the
checked block and loop certificates. -/
structure CompiledKernelRefinement
    (binding : KernelArtifactBinding) (program : CompiledKernelProgram)
    (pe : PE32) (imports : List PEImport)
    (nativeEnvironment : NativeEnvironment) (abi : KernelABIRelation) : Prop where
  artifacts : binding.Valid pe
  exactCfg : program.checked pe imports = true
  blocksSound : ∀ function ∈ program.functions, ∀ block ∈ function.blocks,
    block.SymbolicExecutionSound pe imports
  operations : ∀ operation,
    KernelOperationRefines program pe imports nativeEnvironment abi operation

theorem CompiledKernelRefinement.operation
    {binding : KernelArtifactBinding} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport}
    {nativeEnvironment : NativeEnvironment} {abi : KernelABIRelation}
    (certificate : CompiledKernelRefinement binding program pe imports
      nativeEnvironment abi) (operation : KernelOperation) :
    KernelOperationRefines program pe imports nativeEnvironment abi operation :=
  certificate.operations operation

theorem CompiledKernelRefinement.interpreterStepImplementsMacroStep
    {binding : KernelArtifactBinding} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport}
    {nativeEnvironment : NativeEnvironment} {abi : KernelABIRelation}
    (certificate : CompiledKernelRefinement binding program pe imports
      nativeEnvironment abi) :
    KernelOperationRefines program pe imports nativeEnvironment abi
      .interpreterStep :=
  certificate.operations .interpreterStep

end StageA.Relational.InterpreterKernel
