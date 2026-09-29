# Search positions across two owned string references

`run(value, needle)` consumes both live string references and produces an array
of overlapping match positions. The owned references may share a backing string.
The pinned PE32 `jv_string_indexes` body spans RVA `0x28fc3..0x292ff`, including
two assertion tails. Native disassembly confirms the service order and loop;
pinned upstream C supplies source assistance. Invalid kinds and corrupt objects
are excluded. No neighboring lifted body is required by this local fixture.

The existing `contents` and `release` contracts, shared `string-storage.h` view,
value transport and allocation observer are reused. Views borrow actual bytes
until release; they neither copy the heap nor extend lifetimes. Array creation,
numeric append and validity remain explicit lower services. Their native
implementations run on both comparison sides. The tiny append adapter composes
`jv_number` and `jv_array_append`, preserving their order without search logic.

Empty patterns return an empty array. Embedded NUL and malformed bytes remain
searchable. Positions use the original lead-byte width helper, not a stricter
Unicode decoder. Integer offsets express that behavior without forming a pointer
beyond the backing allocation. Retained input aliases preserve bytes and observe
the two consumed references. Inputs are bounded by INT32_MAX byte lengths.

Comparisons observe result arrays, retained alias contents/reference counts and
allocation lifetimes. A real interpreter case executes the replacement under
`indices`. The complete original search body is trapped on source execution.
Single-threaded execution, valid objects, the native allocator/reference counter
and interpreter are dependencies. Allocation failure is declared as a nonlocal
service outcome but unobserved in this focused handoff, as are arbitrary callbacks
and concurrency. These are finite experimental checks, not strong qualification.
