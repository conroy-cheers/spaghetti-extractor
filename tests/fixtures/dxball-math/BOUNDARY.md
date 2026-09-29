# Numeric tables, projections and pan

Eight complete bodies are selected from the pinned DX-Ball PE32 image:
trig initialization `40d6b0..40d703`, sine/cosine word reads `40d710..40d740`
and `40d740..40d770`, their floating reads `40d770..40d7ac` and
`40d7b0..40d7ec`, coordinate projections `40d7f0..40d817` and
`40d820..40d847`, and pan `403550..40356b`. Image SHA-256 is
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
No original source is consulted. Constants and arithmetic come from these bytes.

The table pointers borrow stable initialized storage and retain correspondence
with the existing scene/gameplay tables. Initialization writes exactly entries
0 through 360 of each table, cosine then sine for each degree. The native
constant is the binary64 value `0x1.1df45a50de271p-6`, not mathematical pi/180.
The floating environment admits the game's normal masked, nearest-rounding
binary64-or-wider arithmetic. Floating status flags and arbitrary x87 control
word changes are not observed. Host libm is checked against every resulting
integer sample and the same source consumer is executed on AArch64.

Readers preserve the original signed remainder policy. Negative multiples use
entry 360. Negating INT32_MIN wraps before signed division, producing index 488;
this historical out-of-table read is not silently replaced with a bounded angle.
Such calls require the corresponding readable neighboring storage. The local
native memory view has 851 words: sine begins at word 0, cosine at word 362, and
the gap and following words retain their input values. This preserves their
aliases without using out-of-bounds C pointer arithmetic. Normal adapters must
publish only the two table ranges written by initialization, not these neighbors.

The floating readers return exact binary fractions of signed table words.
Coordinate projection multiplies modulo 2^32 before signed truncating division
by 1024, then adds the origin modulo 2^32. Pan is exactly truncation of
`(signed(position)*25-8000)/16`, followed by the returned low 32 bits; host
floating-to-int overflow or an approximate centered-pan formula is unnecessary.

These are concrete comparisons and retained portability observations, not a
universal proof for arbitrary floating environments or invalid storage.
