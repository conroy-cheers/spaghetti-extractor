# Borrowed hit-region table

The pinned DX-Ball PE32 SHA256 is
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Inputs are its instructions and existing editor object declarations. No original
game source is used. Native entries are reset `0x40d520..0x40d54e`, definition
`0x40d550..0x40d58d`, and lookup `0x40d590..0x40d5db`. Direct callers found in
the executable belong to the editor (reset, palette definition and mouse input).

The table borrows a separate writable count word and a contiguous span of
`editor_region` records. It shares the editor's actual backing, does not own or
allocate it, and retains no pointers after a synchronous operation. Each record
contains five 32-bit words: left, top, right, bottom, enabled. Reuse the existing
declaration once; no cast between distinct structure types or reconstructed
pointer is a claim about contents or lifetime. There are no external services.

All coordinate and enabled words are admitted. Coordinate comparisons interpret
words as signed x86 values, endpoints are inclusive, every nonzero enabled word
enables a record, and the last matching index wins. Lookup examines indices
`1 <= i < signed(count)` and otherwise returns zero. It preserves the entire
table. Definition receives copied coordinate words, sets enabled to one, and
preserves the count and every other record. Index zero and indices outside the
active count may be defined if their storage is admitted.

Reset stores `requested + 1` modulo 2^32. If that value is negative as an x86
signed word, it leaves records alone. Otherwise it zeroes records zero through
that value inclusive. The actual editor requests 23 and therefore requires 25
records. Do not change this to a conventional count-sized clear.

Capacity is a boundary premise, not an added production bounds check: definition
requires index below capacity; reset with nonnegative wrapped count requires
that count below capacity; lookup with signed count above one requires count no
greater than capacity. This experiment admits 25 records, matching the existing
editor view. It does not claim a larger native allocation, arbitrary corrupt
indices, wrapping native addresses, or behavior outside the admitted storage.
Count storage, record storage and the view descriptor do not overlap. The owner
keeps them live for the call. Other owners may change count or records between
calls, and local cases explicitly exercise those changes.

The local original adapter copies complete initialized storage into the actual
native table at `0x4349d8` and count at `0x435cf4`, executes the entry and copies
everything back, including adjacent guard words. Source hooks replace all three
native bodies. Observations retain every record after each operation, count,
arguments, result and guards. Standalone consumers replay the same expectations
without the original executable or UI. The connected editor binds this same
view to its own table while retaining its existing native-derived observations.

These are practical comparisons with explicit premises, not checked universal
heap summaries or proof-qualified activation. If later program execution reveals
a new input or interaction, retain a local or small connected regression. If the
workbench cannot express or execute that regression without the whole program,
stop and report a tooling gap.
