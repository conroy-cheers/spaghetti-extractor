import StageA.Formal

namespace StageA.Relational

open StageA.Formal

/-! Stable concrete-memory primitives shared by decoding, loaded-image
projection, and relational proofs. -/

def Memory.read32 (memory : Memory) (address : Word) : Word :=
  let b0 := BitVec.zeroExtend 32 (memory address)
  let b1 :=
    (BitVec.zeroExtend 32
      (memory (address + BitVec.ofNat 32 1))).shiftLeft 8
  let b2 :=
    (BitVec.zeroExtend 32
      (memory (address + BitVec.ofNat 32 2))).shiftLeft 16
  let b3 :=
    (BitVec.zeroExtend 32
      (memory (address + BitVec.ofNat 32 3))).shiftLeft 24
  b0 ||| b1 ||| b2 ||| b3

theorem fourBytesAssembleLittleEndian (byte0 byte1 byte2 byte3 : Nat)
    (byte0Bound : byte0 < 256) (byte1Bound : byte1 < 256)
    (byte2Bound : byte2 < 256) (byte3Bound : byte3 < 256) :
    BitVec.setWidth 32 (BitVec.ofNat 8 byte0) |||
          (BitVec.setWidth 32 (BitVec.ofNat 8 byte1)).shiftLeft 8 |||
        (BitVec.setWidth 32 (BitVec.ofNat 8 byte2)).shiftLeft 16 |||
      (BitVec.setWidth 32 (BitVec.ofNat 8 byte3)).shiftLeft 24 =
        BitVec.ofNat 32
          (byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216) := by
  apply BitVec.eq_of_toNat_eq
  simp only [BitVec.toNat_or, BitVec.shiftLeft, BitVec.toNat_setWidth,
    BitVec.toNat_ofNat, Nat.shiftLeft_eq]
  have pow8 : 2 ^ 8 = 256 := by decide
  have pow16 : 2 ^ 16 = 65536 := by decide
  have pow24 : 2 ^ 24 = 16777216 := by decide
  have pow32 : 2 ^ 32 = 4294967296 := by decide
  rw [pow8, pow16, pow24, pow32]
  have byte0Large : byte0 < 4294967296 := Nat.lt_trans byte0Bound (by decide)
  have byte1Large : byte1 < 4294967296 := Nat.lt_trans byte1Bound (by decide)
  have byte2Large : byte2 < 4294967296 := Nat.lt_trans byte2Bound (by decide)
  have byte3Large : byte3 < 4294967296 := Nat.lt_trans byte3Bound (by decide)
  have byte1Shift : byte1 * 256 < 4294967296 := by
    have scaled := Nat.mul_lt_mul_of_pos_right byte1Bound (by decide : 0 < 256)
    exact Nat.lt_trans scaled (by decide)
  have byte2Shift : byte2 * 65536 < 4294967296 := by
    have scaled :=
      Nat.mul_lt_mul_of_pos_right byte2Bound (by decide : 0 < 65536)
    have product : 256 * 65536 = 16777216 := by decide
    rw [product] at scaled
    exact Nat.lt_trans scaled (by decide)
  have byte3Shift : byte3 * 16777216 < 4294967296 := by
    have scaled := Nat.mul_lt_mul_of_pos_right byte3Bound
      (by decide : 0 < 16777216)
    have product : 256 * 16777216 = 4294967296 := by decide
    rw [product] at scaled
    exact scaled
  have low16Bound : byte0 + byte1 * 256 < 65536 := by
    have byte1Next : byte1 + 1 <= 256 := by omega
    calc
      byte0 + byte1 * 256 < 256 + byte1 * 256 :=
        Nat.add_lt_add_right byte0Bound _
      _ = (byte1 + 1) * 256 := by simp [Nat.add_mul, Nat.add_comm]
      _ <= 256 * 256 := Nat.mul_le_mul_right 256 byte1Next
      _ = 65536 := by decide
  have low24Bound :
      byte0 + byte1 * 256 + byte2 * 65536 < 16777216 := by
    have byte2Next : byte2 + 1 <= 256 := by omega
    calc
      byte0 + byte1 * 256 + byte2 * 65536 <
          65536 + byte2 * 65536 :=
        Nat.add_lt_add_right low16Bound _
      _ = (byte2 + 1) * 65536 := by simp [Nat.add_mul, Nat.add_comm]
      _ <= 256 * 65536 := Nat.mul_le_mul_right 65536 byte2Next
      _ = 16777216 := by decide
  have totalBound :
      byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 <
        4294967296 := by
    have byte3Next : byte3 + 1 <= 256 := by omega
    calc
      byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 <
          16777216 + byte3 * 16777216 :=
        Nat.add_lt_add_right low24Bound _
      _ = (byte3 + 1) * 16777216 := by simp [Nat.add_mul, Nat.add_comm]
      _ <= 256 * 16777216 := Nat.mul_le_mul_right 16777216 byte3Next
      _ = 4294967296 := by decide
  rw [Nat.mod_eq_of_lt byte0Bound, Nat.mod_eq_of_lt byte0Large,
    Nat.mod_eq_of_lt byte1Bound, Nat.mod_eq_of_lt byte1Large,
    Nat.mod_eq_of_lt byte1Shift, Nat.mod_eq_of_lt byte2Bound,
    Nat.mod_eq_of_lt byte2Large, Nat.mod_eq_of_lt byte2Shift,
    Nat.mod_eq_of_lt byte3Bound, Nat.mod_eq_of_lt byte3Large,
    Nat.mod_eq_of_lt byte3Shift, Nat.mod_eq_of_lt totalBound]
  have low16 : byte0 ||| byte1 * 256 = byte0 + byte1 * 256 := by
    calc
      byte0 ||| byte1 * 256 = byte1 * 256 ||| byte0 := Nat.or_comm _ _
      _ = byte1 * 256 + byte0 := by
        simpa [pow8, Nat.mul_comm] using
          (Nat.two_pow_add_eq_or_of_lt (i := 8) byte0Bound byte1).symm
      _ = byte0 + byte1 * 256 := Nat.add_comm _ _
  rw [low16]
  have low24 : (byte0 + byte1 * 256) ||| byte2 * 65536 =
      byte0 + byte1 * 256 + byte2 * 65536 := by
    calc
      (byte0 + byte1 * 256) ||| byte2 * 65536 =
          byte2 * 65536 ||| (byte0 + byte1 * 256) := Nat.or_comm _ _
      _ = byte2 * 65536 + (byte0 + byte1 * 256) := by
        simpa [pow16, Nat.mul_comm] using
          (Nat.two_pow_add_eq_or_of_lt (i := 16) low16Bound byte2).symm
      _ = byte0 + byte1 * 256 + byte2 * 65536 := by omega
  rw [low24]
  calc
    (byte0 + byte1 * 256 + byte2 * 65536) ||| byte3 * 16777216 =
        byte3 * 16777216 ||| (byte0 + byte1 * 256 + byte2 * 65536) :=
      Nat.or_comm _ _
    _ = byte3 * 16777216 +
        (byte0 + byte1 * 256 + byte2 * 65536) := by
      simpa [pow24, Nat.mul_comm] using
        (Nat.two_pow_add_eq_or_of_lt (i := 24) low24Bound byte3).symm
    _ = byte0 + byte1 * 256 + byte2 * 65536 + byte3 * 16777216 := by
      omega

end StageA.Relational
