import StageA.RelationalInterpreterX87ReplayBridgeTarget

namespace StageA.Relational.InterpreterX87ReplayMemoryFrame

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterX87ReplayBridgeTarget

/-- The write footprint of two consecutive replay phases. -/
def footprintUnion (left right : CandidateFootprint) : CandidateFootprint :=
  fun address => left address ∨ right address

/-- Restrict both sides of a checked disjointness fact. -/
theorem CandidateFootprintsDisjoint.mono
    {left right narrowerLeft narrowerRight : CandidateFootprint}
    (disjoint : CandidateFootprintsDisjoint left right)
    (leftSubset : ∀ address, narrowerLeft address -> left address)
    (rightSubset : ∀ address, narrowerRight address -> right address) :
    CandidateFootprintsDisjoint narrowerLeft narrowerRight := by
  intro address leftMember rightMember
  exact disjoint address
    (leftSubset address leftMember) (rightSubset address rightMember)

/-- A bounded byte range beginning at a private-stack offset belongs to the
twenty-byte saved call frame. -/
theorem nativeX87ReplayPrivateStackByteRange_subset
    (caller : MachineState) (offset bytes : Nat)
    (bounded : offset + bytes <= 20) :
    ∀ address,
      nativeX87ReplayByteRange
          (caller.registers.esp - BitVec.ofNat 32 20 +
            BitVec.ofNat 32 offset) bytes address ->
        nativeX87ReplayPrivateStackFootprint caller address := by
  intro address member
  rcases member with ⟨byte, byteBefore, rfl⟩
  exact ⟨offset + byte, by omega, by
    simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩

/-- A bounded byte range beginning at a replay-frame offset belongs to the
complete replay frame. -/
theorem nativeX87ReplayFrameByteRange_subset
    (frameAddress : Word) (offset bytes : Nat)
    (bounded : offset + bytes <= nativeX87ReplayFrameBytes) :
    ∀ address,
      nativeX87ReplayByteRange
          (frameAddress + BitVec.ofNat 32 offset) bytes address ->
        nativeX87ReplayFrameFootprint frameAddress address := by
  intro address member
  rcases member with ⟨byte, byteBefore, rfl⟩
  exact ⟨offset + byte, by omega, by
    simp [BitVec.add_assoc, ← BitVec.ofNat_add]⟩

/-- Compose two framed memory transitions without forcing either transition
to be widened to the other's footprint first. -/
theorem MemoryAgreesOutside.compose
    {left right : CandidateFootprint}
    {before middle after : Memory}
    (first : MemoryAgreesOutside left middle before)
    (second : MemoryAgreesOutside right after middle) :
    MemoryAgreesOutside (footprintUnion left right) after before := by
  intro address outside
  have outsideLeft : ¬ left address := fun member =>
    outside (Or.inl member)
  have outsideRight : ¬ right address := fun member =>
    outside (Or.inr member)
  exact (second address outsideRight).trans (first address outsideLeft)

/-- Reuse a frame under a larger footprint. -/
theorem MemoryAgreesOutside.widen
    {small large : CandidateFootprint}
    {after before : Memory}
    (frame : MemoryAgreesOutside small after before)
    (subset : ∀ address, small address -> large address) :
    MemoryAgreesOutside large after before := by
  intro address outside
  exact frame address (fun member => outside (subset address member))

/-- A framed transition preserves every byte in a disjoint byte range. -/
theorem MemoryAgreesOutside.readBytes_of_disjoint
    {footprint : CandidateFootprint} {after before : Memory}
    (frame : MemoryAgreesOutside footprint after before)
    {base : Word} {bytes : Nat}
    (disjoint : CandidateFootprintsDisjoint footprint
      (nativeX87ReplayByteRange base bytes)) :
    Engine.readBytes after base bytes = Engine.readBytes before base bytes := by
  unfold Engine.readBytes
  apply List.map_congr_left
  intro offset member
  exact frame _ (fun footprintMember =>
    disjoint _ footprintMember
      ⟨offset, List.mem_range.mp member, rfl⟩)

/-- A framed transition preserves a disjoint 32-bit cell. -/
theorem MemoryAgreesOutside.read32_of_disjoint
    {footprint : CandidateFootprint} {after before : Memory}
    (frame : MemoryAgreesOutside footprint after before)
    {base : Word}
    (disjoint : CandidateFootprintsDisjoint footprint
      (nativeX87ReplayByteRange base 4)) :
    Memory.read32 after base = Memory.read32 before base := by
  unfold Memory.read32
  rw [frame base (fun footprintMember =>
    disjoint base footprintMember ⟨0, by omega, by simp⟩)]
  rw [frame (base + BitVec.ofNat 32 1)
    (fun footprintMember =>
      disjoint _ footprintMember ⟨1, by omega, rfl⟩)]
  rw [frame (base + BitVec.ofNat 32 2)
    (fun footprintMember =>
      disjoint _ footprintMember ⟨2, by omega, rfl⟩)]
  rw [frame (base + BitVec.ofNat 32 3)
    (fun footprintMember =>
      disjoint _ footprintMember ⟨3, by omega, rfl⟩)]

/-- Equality of machine states transports a top-of-stack dword read without
unfolding either state's construction in downstream replay proofs. -/
theorem MachineState.read32Top_congr
    {left right : MachineState} (statesEqual : left = right) :
    Memory.read32 left.memory left.registers.esp =
      Memory.read32 right.memory right.registers.esp := by
  cases statesEqual
  rfl

/-- A concrete dword write has exactly its four-byte footprint. -/
theorem MemoryAgreesOutside.write32ByteRange
    (before : Memory) (address value : Word) :
    MemoryAgreesOutside (nativeX87ReplayByteRange address 4)
      (before.write32 address value) before := by
  apply MemoryAgreesOutside.write32Inside
  intro byte byteBefore
  exact ⟨byte, byteBefore, rfl⟩

/-- A concrete x87 frame write has exactly the byte-list footprint. -/
theorem MemoryAgreesOutside.writeX87ByteRange
    (before : Memory) (address : Word) (bytes : List (BitVec 8)) :
    MemoryAgreesOutside
      (nativeX87ReplayByteRange address bytes.length)
      (writeX87FrameBytes before address bytes) before := by
  apply MemoryAgreesOutside.writeX87FrameInside
  intro offset offsetBefore
  exact ⟨offset, offsetBefore, rfl⟩

/-- Translation by a common 32-bit base preserves disjointness between two
bounded offset ranges.  The proof works modulo `2^32`, so callers do not need
an artificial no-wrap premise on the common base. -/
theorem translatedByteRangesDisjoint
    (base : Word) (leftOffset leftBytes rightOffset rightBytes : Nat)
    (leftBounded : leftOffset + leftBytes <= 2 ^ 32)
    (rightBounded : rightOffset + rightBytes <= 2 ^ 32)
    (separated :
      leftOffset + leftBytes <= rightOffset ∨
        rightOffset + rightBytes <= leftOffset) :
    CandidateFootprintsDisjoint
      (nativeX87ReplayByteRange
        (base + BitVec.ofNat 32 leftOffset) leftBytes)
      (nativeX87ReplayByteRange
        (base + BitVec.ofNat 32 rightOffset) rightBytes) := by
  intro address leftMember rightMember
  rcases leftMember with ⟨leftByte, leftByteBounded, leftAddress⟩
  rcases rightMember with ⟨rightByte, rightByteBounded, rightAddress⟩
  subst address
  have translated :
      base + BitVec.ofNat 32 (leftOffset + leftByte) =
        base + BitVec.ofNat 32 (rightOffset + rightByte) := by
    simpa only [BitVec.add_assoc, ← BitVec.ofNat_add] using rightAddress
  have offsets :
      BitVec.ofNat 32 (leftOffset + leftByte) =
        BitVec.ofNat 32 (rightOffset + rightByte) := by
    have cancelled := congrArg (fun value => value - base) translated
    simpa [BitVec.add_comm] using cancelled
  have naturals := congrArg BitVec.toNat offsets
  have leftLess : leftOffset + leftByte < 2 ^ 32 := by omega
  have rightLess : rightOffset + rightByte < 2 ^ 32 := by omega
  simp only [BitVec.toNat_ofNat, Nat.mod_eq_of_lt leftLess,
    Nat.mod_eq_of_lt rightLess] at naturals
  omega

/-- A dword write at one translated offset preserves a dword read at a
disjoint translated offset.  This packages the footprint construction and
modular-address disjointness proof so replay clients compose one checked fact
instead of rebuilding both arguments. -/
theorem Memory.read32_write32_translated_of_disjoint
    (memory : Memory) (base : Word)
    (writeOffset readOffset : Nat) (value : Word)
    (writeBounded : writeOffset + 4 <= 2 ^ 32)
    (readBounded : readOffset + 4 <= 2 ^ 32)
    (separated :
      writeOffset + 4 <= readOffset ∨ readOffset + 4 <= writeOffset) :
    Memory.read32
        (memory.write32 (base + BitVec.ofNat 32 writeOffset) value)
        (base + BitVec.ofNat 32 readOffset) =
      Memory.read32 memory (base + BitVec.ofNat 32 readOffset) := by
  exact MemoryAgreesOutside.read32_of_disjoint
    (MemoryAgreesOutside.write32ByteRange memory
      (base + BitVec.ofNat 32 writeOffset) value)
    (translatedByteRangesDisjoint base writeOffset 4 readOffset 4
      writeBounded readBounded separated)

/-- Repeated affine offsets from a register evaluate to the corresponding
concrete modular additions. -/
theorem Expr.eval_inputReg_offset_offset
    (register : Reg) (first second : Nat) (state : MachineState) :
    (((Expr.inputReg register).offset first).offset second).eval state =
      state.registers.get register + BitVec.ofNat 32 first +
        BitVec.ofNat 32 second := by
  cases first <;> cases second <;>
    simp [Expr.offset, Expr.addNormalized, Expr.eval, Registers.get]
  split
  · rename_i first second equalZero
    have offsetZero :
        BitVec.ofNat 32 (first + 1 + (second + 1)) =
          BitVec.ofNat 32 0 := by
      apply BitVec.eq_of_toNat_eq
      simp [equalZero]
    cases register <;>
      simp [Expr.eval, Registers.get, ← BitVec.ofNat_add,
        BitVec.add_assoc, offsetZero]
  · rename_i first second notZero
    have offsetMod :
        BitVec.ofNat 32 ((first + 1 + (second + 1)) % (2 ^ 32)) =
          BitVec.ofNat 32 (first + 1 + (second + 1)) := by
      apply BitVec.eq_of_toNat_eq
      simp
    cases register <;>
      simp [Expr.eval, Registers.get, ← BitVec.ofNat_add,
        BitVec.add_assoc, offsetMod]

/-- Four consecutive 32-bit addresses remain pairwise distinct even when the
base is close to the top of the flat address space. -/
theorem Memory.read32_write32_same
    (memory : Memory) (address value : Word) :
    Memory.read32 (memory.write32 address value) address = value := by
  have h10 : address + BitVec.ofNat 32 1 ≠ address := by
    bv_decide
  have h20 : address + BitVec.ofNat 32 2 ≠ address := by
    bv_decide
  have h21 :
      address + BitVec.ofNat 32 2 ≠ address + BitVec.ofNat 32 1 := by
    bv_decide
  have h30 : address + BitVec.ofNat 32 3 ≠ address := by
    bv_decide
  have h31 :
      address + BitVec.ofNat 32 3 ≠ address + BitVec.ofNat 32 1 := by
    bv_decide
  have h32 :
      address + BitVec.ofNat 32 3 ≠ address + BitVec.ofNat 32 2 := by
    bv_decide
  simp [Memory.read32, Memory.write32, h10, h20, h21, h30, h31, h32]
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  simp only [BitVec.getLsbD_or, BitVec.getLsbD_shiftLeft,
    BitVec.getLsbD_setWidth, BitVec.getLsbD_extractLsb']
  by_cases i0 : i < 8
  · have i16 : i < 16 := by omega
    have i24 : i < 24 := by omega
    simp [i0, i16, i24, hi]
  by_cases i1 : i < 16
  · have i24 : i < 24 := by omega
    have byte : i - 8 < 8 := by omega
    have width : i - 8 < 32 := by omega
    have index : 8 + (i - 8) = i := by omega
    simp [i0, i1, i24, hi, byte, width, index]
  by_cases i2 : i < 24
  · have firstOut : ¬i - 8 < 8 := by omega
    have byte : i - 16 < 8 := by omega
    have width8 : i - 8 < 32 := by omega
    have width16 : i - 16 < 32 := by omega
    have index : 16 + (i - 16) = i := by omega
    simp [i0, i1, i2, hi, firstOut, byte, width8, width16, index]
  · have firstOut : ¬i - 8 < 8 := by omega
    have secondOut : ¬i - 16 < 8 := by omega
    have byte : i - 24 < 8 := by omega
    have width8 : i - 8 < 32 := by omega
    have width16 : i - 16 < 32 := by omega
    have width24 : i - 24 < 32 := by omega
    have index : 24 + (i - 24) = i := by omega
    simp [i0, i1, i2, hi, firstOut, secondOut, byte,
      width8, width16, width24, index]

/-- The executor implements `SETcc r/m8` through a 32-bit write whose upper
three bytes are read back from memory.  This identity checks that the resulting
word replaces exactly the low byte with the selected one-bit condition. -/
theorem Memory.setConditionLowByte
    (old0 old1 old2 old3 : BitVec 8) (condition : BitVec 1) :
    (BitVec.ofNat 32 condition.toNat &&& BitVec.ofNat 32 0xff |||
      (BitVec.setWidth 32 old1 <<< 8 |||
        (BitVec.setWidth 32 old2 <<< 16 |||
          BitVec.setWidth 32 old3 <<< 24))) =
      (((BitVec.setWidth 32 old0 |||
            BitVec.setWidth 32 old1 <<< 8 |||
          BitVec.setWidth 32 old2 <<< 16 |||
          BitVec.setWidth 32 old3 <<< 24) &&&
        BitVec.ofNat 32 0xffffff00) |||
        BitVec.ofNat 32 condition.toNat) := by
  have conditionValue :
      condition = BitVec.ofNat 1 0 ∨ condition = BitVec.ofNat 1 1 := by
    have bounded := condition.isLt
    have values : condition.toNat = 0 ∨ condition.toNat = 1 := by
      omega
    rcases values with zero | one
    · left
      apply BitVec.eq_of_toNat_eq
      simp [zero]
    · right
      apply BitVec.eq_of_toNat_eq
      simp [one]
  rcases conditionValue with rfl | rfl <;>
    apply BitVec.eq_of_getLsbD_eq <;>
    intro index bounded
  all_goals
    have possible :
        index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
        index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
        index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
        index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
        index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
        index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
        index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
        index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
      omega
    rcases possible with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp

/-- Normalize the executor's conditional encoding of an input EFLAGS bit to
the one-bit natural encoding used by the engine frame. -/
theorem inputFlagConditionalUnitEval (input : MachineState) (bit : Nat) :
    (if (BoolExpr.inputFlag bit).toWord.eval input = BitVec.ofNat 32 1 then
        BitVec.ofNat 32 1
      else
        BitVec.ofNat 32 0) =
      BitVec.ofNat 32 (input.eflags.extractLsb' bit 1).toNat := by
  have conditionValue :
      input.eflags.extractLsb' bit 1 = BitVec.ofNat 1 0 ∨
        input.eflags.extractLsb' bit 1 = BitVec.ofNat 1 1 := by
    have bounded := (input.eflags.extractLsb' bit 1).isLt
    have values :
        (input.eflags.extractLsb' bit 1).toNat = 0 ∨
          (input.eflags.extractLsb' bit 1).toNat = 1 := by
      omega
    rcases values with zero | one
    · left
      apply BitVec.eq_of_toNat_eq
      simp [zero]
    · right
      apply BitVec.eq_of_toNat_eq
      simp [one]
  rcases conditionValue with conditionZero | conditionOne
  · simp [BoolExpr.toWord, StageA.Formal.Expr.eval, conditionZero]
  · simp [BoolExpr.toWord, StageA.Formal.Expr.eval, conditionOne]

/-- Replacing the low byte of a canonical one-bit engine flag field produces
the canonical encoding of the successor one-bit flag. -/
theorem replaceEncodedFlagLowByte
    (before after : BitVec 1) :
    (BitVec.ofNat 32 before.toNat &&& BitVec.ofNat 32 0xffffff00) |||
        BitVec.ofNat 32 after.toNat =
      BitVec.ofNat 32 after.toNat := by
  have beforeValue :
      before = BitVec.ofNat 1 0 ∨ before = BitVec.ofNat 1 1 := by
    have bounded := before.isLt
    have values : before.toNat = 0 ∨ before.toNat = 1 := by omega
    rcases values with zero | one
    · left
      apply BitVec.eq_of_toNat_eq
      simp [zero]
    · right
      apply BitVec.eq_of_toNat_eq
      simp [one]
  have afterValue :
      after = BitVec.ofNat 1 0 ∨ after = BitVec.ofNat 1 1 := by
    have bounded := after.isLt
    have values : after.toNat = 0 ∨ after.toNat = 1 := by omega
    rcases values with zero | one
    · left
      apply BitVec.eq_of_toNat_eq
      simp [zero]
    · right
      apply BitVec.eq_of_toNat_eq
      simp [one]
  rcases beforeValue with rfl | rfl <;>
    rcases afterValue with rfl | rfl <;>
      decide

/-- The exact four bytes emitted by a dword write use the engine ABI's
little-endian encoding. -/
theorem Engine.readBytes_write32_same
    (memory : Memory) (address value : Word) :
    Engine.readBytes (memory.write32 address value) address 4 =
      Engine.encodeLittleEndian 4 value.toNat := by
  simp [Engine.readBytes, Engine.encodeLittleEndian, Memory.write32]
  intro offset bounded
  have possible :
      offset = 0 ∨ offset = 1 ∨ offset = 2 ∨ offset = 3 := by
    omega
  rcases possible with rfl | rfl | rfl | rfl <;>
    apply BitVec.eq_of_toNat_eq <;>
    simp [Nat.shiftRight_eq_div_pow]

/-- The four-byte little-endian encoding is complete for `Memory.read32`.
This converse lets output proofs establish a compact dword equation and expose
the exact engine ABI bytes without replaying the write implementation. -/
theorem Engine.readBytes_eq_encodeLittleEndian4_of_read32
    (memory : Memory) (address value : Word)
    (exact : Memory.read32 memory address = value) :
    Engine.readBytes memory address 4 =
      Engine.encodeLittleEndian 4 value.toNat := by
  let byte0 := (memory address).toNat
  let byte1 := (memory (address + BitVec.ofNat 32 1)).toNat
  let byte2 := (memory (address + BitVec.ofNat 32 2)).toNat
  let byte3 := (memory (address + BitVec.ofNat 32 3)).toNat
  have byte0Bound : byte0 < 256 := by simpa [byte0] using (memory address).isLt
  have byte1Bound : byte1 < 256 := by
    simpa [byte1] using (memory (address + BitVec.ofNat 32 1)).isLt
  have byte2Bound : byte2 < 256 := by
    simpa [byte2] using (memory (address + BitVec.ofNat 32 2)).isLt
  have byte3Bound : byte3 < 256 := by
    simpa [byte3] using (memory (address + BitVec.ofNat 32 3)).isLt
  have sumBound :
      byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 <
        2 ^ 32 := by
    omega
  have assembled :=
    fourBytesAssembleLittleEndian byte0 byte1 byte2 byte3
      byte0Bound byte1Bound byte2Bound byte3Bound
  have wordExact :
      BitVec.ofNat 32
          (byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216) =
        value := by
    rw [← exact]
    simpa [Memory.read32, byte0, byte1, byte2, byte3] using assembled.symm
  have naturalExact :
      byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 =
        value.toNat := by
    have := congrArg BitVec.toNat wordExact
    simpa [Nat.mod_eq_of_lt sumBound] using this
  unfold Engine.readBytes Engine.encodeLittleEndian
  apply List.map_congr_left
  intro offset member
  have bounded := List.mem_range.mp member
  have possible :
      offset = 0 ∨ offset = 1 ∨ offset = 2 ∨ offset = 3 := by
    omega
  rcases possible with rfl | rfl | rfl | rfl
  all_goals apply BitVec.eq_of_toNat_eq
  all_goals simp only [BitVec.toNat_ofNat]
  · have digit : byte0 = value.toNat % 256 := by omega
    simpa [byte0] using digit
  · have digit : byte1 = value.toNat / 256 % 256 := by omega
    simpa [byte1] using digit
  · have digit : byte2 = value.toNat / 65536 % 256 := by omega
    simpa [byte2] using digit
  · have digit : byte3 = value.toNat / 16777216 % 256 := by omega
    simpa [byte3] using digit

private theorem mergeNativeStatusMask_zero
    (input value : Word) :
    (input &&& BitVec.ofNat 32 0xfffff32a) |||
        (((input &&& ~~~(BitVec.ofNat 32 0)) |||
          (value &&& BitVec.ofNat 32 0)) &&&
            BitVec.ofNat 32 0x0cd5) =
      (input &&& ~~~(BitVec.ofNat 32 0)) |||
        (value &&& BitVec.ofNat 32 0) := by
  apply BitVec.eq_of_getElem_eq
  intro index bounded
  have possible :
      index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
      index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
      index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
      index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
      index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
      index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
      index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
      index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
    omega
  rcases possible with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp

private theorem mergeNativeStatusMask_compare
    (input value : Word) :
    (input &&& BitVec.ofNat 32 0xfffff32a) |||
        (((input &&& ~~~(BitVec.ofNat 32 0x8d5)) |||
          (value &&& BitVec.ofNat 32 0x8d5)) &&&
            BitVec.ofNat 32 0x0cd5) =
      (input &&& ~~~(BitVec.ofNat 32 0x8d5)) |||
        (value &&& BitVec.ofNat 32 0x8d5) := by
  apply BitVec.eq_of_getElem_eq
  intro index bounded
  have possible :
      index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
      index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
      index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
      index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
      index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
      index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
      index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
      index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
    omega
  rcases possible with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp

/-- The native bridge copies the five x87 status flags plus AF from the result
and preserves every other EFLAGS bit from the input.  The extra AF bit is
benign because the qualified x87 response never writes it. -/
theorem applyX87FlagsEffect_mergeNativeStatusMask
    (input : Word) (command : StageA.X87.Command)
    (response : StageA.X87.Response)
    (maskExact :
      response.eflagsWriteMask = command.eflagsWriteMask) :
    (input &&& BitVec.ofNat 32 0xfffff32a) |||
        (applyX87FlagsEffect input response &&&
          BitVec.ofNat 32 0x0cd5) =
      applyX87FlagsEffect input response := by
  have maskCases :
      command.eflagsWriteMask = BitVec.ofNat 32 0 ∨
        command.eflagsWriteMask = BitVec.ofNat 32 0x8d5 := by
    cases command <;>
      simp [StageA.X87.Command.eflagsWriteMask]
    case compareStack mode destination index pop =>
      cases destination <;>
        simp [StageA.X87.Command.eflagsWriteMask]
  rcases maskCases with maskZero | maskStatus
  · have responseMask :
        response.eflagsWriteMask = BitVec.ofNat 32 0 :=
      maskExact.trans maskZero
    simpa [applyX87FlagsEffect, responseMask] using
      mergeNativeStatusMask_zero input response.eflagsValue
  · have responseMask :
        response.eflagsWriteMask = BitVec.ofNat 32 0x8d5 :=
      maskExact.trans maskStatus
    simpa [applyX87FlagsEffect, responseMask] using
      mergeNativeStatusMask_compare input response.eflagsValue

/-- Qualified x87 status updates cannot reintroduce RF or VM after the exact
CPL3 PUSHFD image condition has established that both are clear. -/
theorem applyX87FlagsEffect_pushImage
    (input : Word) (command : StageA.X87.Command)
    (response : StageA.X87.Response)
    (maskExact :
      response.eflagsWriteMask = command.eflagsWriteMask)
    (inputExact :
      input &&& BitVec.ofNat 32 0xfffcffff = input) :
    applyX87FlagsEffect input response &&&
        BitVec.ofNat 32 0xfffcffff =
      applyX87FlagsEffect input response := by
  have bit16 :=
    congrArg (fun word : Word => word[16]) inputExact
  have bit17 :=
    congrArg (fun word : Word => word[17]) inputExact
  have inputBit16 : input[16] = false := by simpa using bit16.symm
  have inputBit17 : input[17] = false := by simpa using bit17.symm
  have maskCases :
      command.eflagsWriteMask = BitVec.ofNat 32 0 ∨
        command.eflagsWriteMask = BitVec.ofNat 32 0x8d5 := by
    cases command <;>
      simp [StageA.X87.Command.eflagsWriteMask]
    case compareStack mode destination index pop =>
      cases destination <;>
        simp [StageA.X87.Command.eflagsWriteMask]
  rcases maskCases with maskZero | maskStatus
  · have responseMask :
        response.eflagsWriteMask = BitVec.ofNat 32 0 :=
      maskExact.trans maskZero
    apply BitVec.eq_of_getElem_eq
    intro index bounded
    have possible :
        index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
        index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
        index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
        index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
        index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
        index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
        index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
        index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
      omega
    rcases possible with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp [applyX87FlagsEffect, responseMask, inputBit16, inputBit17]
  · have responseMask :
        response.eflagsWriteMask = BitVec.ofNat 32 0x8d5 :=
      maskExact.trans maskStatus
    apply BitVec.eq_of_getElem_eq
    intro index bounded
    have possible :
        index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
        index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
        index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
        index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
        index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
        index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
        index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
        index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
      omega
    rcases possible with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp [applyX87FlagsEffect, responseMask, inputBit16, inputBit17]

-- The symbolic input-flags word reconstructs every concrete EFLAGS bit.
theorem inputEflagsExpressionEval (input : MachineState) :
    inputEflagsExpression.eval input = input.eflags :=
  StageA.Formal.inputEflagsExpression_eval input

theorem updateFlagExpressionEvalSourceBit
    (input : MachineState) (base source : Expr) (index : Nat)
    (bounded : index < 32)
    (baseExact : base.eval input = source.eval input) :
    (updateFlagExpression base index (some (.bit source index))).eval input =
      source.eval input := by
  have powerBounded : 2 ^ index < 2 ^ 32 :=
    Nat.pow_lt_pow_right (by decide) bounded
  have clearMaskBounded :
      2 ^ 32 - 1 - 2 ^ index < 2 ^ 32 :=
    Nat.lt_of_le_of_lt (Nat.sub_le _ _) (by decide)
  have clearMaskExact :
      BitVec.ofNat 32 (2 ^ 32 - 1 - 2 ^ index) =
        ~~~(BitVec.twoPow 32 index) := by
    apply BitVec.eq_of_toNat_eq
    simp [BitVec.toNat_twoPow, Nat.mod_eq_of_lt powerBounded,
      Nat.mod_eq_of_lt clearMaskBounded]
  have sourceTestBit :
      (source.eval input).toNat.testBit index =
        (source.eval input)[index] :=
    (BitVec.getElem_eq_testBit_toNat
      (source.eval input) index bounded).symm
  apply BitVec.eq_of_getElem_eq
  intro observed observedBounded
  by_cases same : observed = index
  · subst observed
    cases bit : (source.eval input)[index] <;>
      simp [updateFlagExpression, StageA.Formal.Expr.eval,
        BoolExpr.eval, BoolExpr.toWord_eval, baseExact, clearMaskExact,
        sourceTestBit, bounded, bit]
  · cases bit : (source.eval input)[index] <;>
      simp [updateFlagExpression, StageA.Formal.Expr.eval,
        BoolExpr.eval, BoolExpr.toWord_eval, baseExact, clearMaskExact,
        sourceTestBit, observedBounded, same, bit] <;>
      omega

theorem updateFlagExpressionEvalCongrValue
    (input : MachineState) (base : Expr) (index : Nat)
    (left right : BoolExpr)
    (valueExact : left.eval input = right.eval input) :
    (updateFlagExpression base index (some left)).eval input =
      (updateFlagExpression base index (some right)).eval input := by
  simp only [updateFlagExpression, StageA.Formal.Expr.eval,
    BoolExpr.toWord_eval, valueExact]

/-- Re-applying a concrete input flag to an expression already equal to the
input EFLAGS word is observationally the identity. -/
theorem updateFlagExpressionEvalInputFlag
    (input : MachineState) (base : Expr) (index : Nat)
    (bounded : index < 32)
    (baseExact : base.eval input = input.eflags) :
    (updateFlagExpression base index (some (.inputFlag index))).eval input =
      input.eflags := by
  have valueExact :
      BoolExpr.eval input (.inputFlag index) =
        BoolExpr.eval input (.bit inputEflagsExpression index) := by
    change
      (input.eflags.extractLsb' index 1 == BitVec.ofNat 1 1) =
        (inputEflagsExpression.eval input).toNat.testBit index
    calc
      (input.eflags.extractLsb' index 1 == BitVec.ofNat 1 1) =
          input.eflags[index] :=
        (BitVec.getElem_eq_extractLsb' input.eflags index bounded).symm
      _ = input.eflags.toNat.testBit index :=
        BitVec.getElem_eq_testBit_toNat input.eflags index bounded
      _ = (inputEflagsExpression.eval input).toNat.testBit index := by
        rw [inputEflagsExpressionEval input]
  calc
    (updateFlagExpression base index (some (.inputFlag index))).eval input =
        (updateFlagExpression base index
          (some (.bit inputEflagsExpression index))).eval input :=
      updateFlagExpressionEvalCongrValue input base index _ _ valueExact
    _ = input.eflags :=
      (updateFlagExpressionEvalSourceBit input base
        inputEflagsExpression index bounded
        (baseExact.trans (inputEflagsExpressionEval input).symm)).trans
          (inputEflagsExpressionEval input)

/-- The initial symbolic EFLAGS expression reconstructs the complete concrete
EFLAGS word, including bits that are not represented by `FlagsExpr`.  This is
the stable bridge used by POPFD replay proofs. -/
theorem initialSymbolicEflagsEval (input : MachineState) :
    initialSymbolic.eflagsExpression.eval input = input.eflags := by
  let carry :=
    updateFlagExpression inputEflagsExpression 0 (some (.inputFlag 0))
  let parity := updateFlagExpression carry 2 (some (.inputFlag 2))
  let zero := updateFlagExpression parity 6 (some (.inputFlag 6))
  let sign := updateFlagExpression zero 7 (some (.inputFlag 7))
  let overflow := updateFlagExpression sign 11 (some (.inputFlag 11))
  have baseExact := inputEflagsExpressionEval input
  have carryExact : carry.eval input = input.eflags :=
    updateFlagExpressionEvalInputFlag input inputEflagsExpression 0
      (by decide) baseExact
  have parityExact : parity.eval input = input.eflags :=
    updateFlagExpressionEvalInputFlag input carry 2
      (by decide) carryExact
  have zeroExact : zero.eval input = input.eflags :=
    updateFlagExpressionEvalInputFlag input parity 6
      (by decide) parityExact
  have signExact : sign.eval input = input.eflags :=
    updateFlagExpressionEvalInputFlag input zero 7
      (by decide) zeroExact
  have overflowExact : overflow.eval input = input.eflags :=
    updateFlagExpressionEvalInputFlag input sign 11
      (by decide) signExact
  simpa [SymbolicBehavior.eflagsExpression, initialSymbolic,
    FlagsExpr.applyToExpression, carry, parity, zero, sign, overflow] using
      overflowExact

/-- `POPFD` evaluation is extensional in the two input expressions.  Keeping
this theorem abstract in the expressions prevents downstream proofs from
expanding the complete initial-EFLAGS expression. -/
theorem popFlagsCpl3Expression_eval_congr
    (current popped : Expr) (left right : MachineState)
    (currentExact : current.eval left = current.eval right)
    (poppedExact : popped.eval left = popped.eval right) :
    (popFlagsCpl3Expression current popped).eval left =
      (popFlagsCpl3Expression current popped).eval right := by
  simp only [popFlagsCpl3Expression, updateFlagExpression,
    StageA.Formal.Expr.eval, BoolExpr.eval, BoolExpr.toWord_eval]
  rw [currentExact, poppedExact]

#print axioms MemoryAgreesOutside.compose
#print axioms MemoryAgreesOutside.read32_of_disjoint
#print axioms translatedByteRangesDisjoint
#print axioms Memory.read32_write32_translated_of_disjoint
#print axioms Expr.eval_inputReg_offset_offset
#print axioms Memory.read32_write32_same
#print axioms Memory.setConditionLowByte
#print axioms Engine.readBytes_eq_encodeLittleEndian4_of_read32
#print axioms applyX87FlagsEffect_mergeNativeStatusMask
#print axioms applyX87FlagsEffect_pushImage
#print axioms inputFlagConditionalUnitEval
#print axioms replaceEncodedFlagLowByte
#print axioms inputEflagsExpressionEval
#print axioms updateFlagExpressionEvalInputFlag
#print axioms initialSymbolicEflagsEval
#print axioms popFlagsCpl3Expression_eval_congr

end StageA.Relational.InterpreterX87ReplayMemoryFrame
