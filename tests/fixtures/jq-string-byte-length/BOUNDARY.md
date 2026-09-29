# Consuming byte length and a body-independent string view

`run(value)` consumes one live jq string reference, returning its stored byte
length as a signed 32-bit integer. It includes embedded NUL and malformed UTF-8.
The pinned DLL entry owns RVA `0x28e32..0x28eac`, including its assertion tail.
Invalid kinds, corrupt pointers/headers and lengths beyond INT32_MAX are excluded.
Retained aliases keep their bytes and observe one reference released. The final
reference releases the actual allocation through the existing release service.

Reuse the exact `contents` and `release` contracts and live-value transport.
However, the previous contents adapter called this operation itself. That adapter
cannot be used when replacing the operation: a service declaration does not imply
body independence. The shared `jq-string-slice/string-storage.h` now reads the
existing allocation directly, using one reviewed layout shared by the PE32 DLL
and portable source backend. It reads the length/hash word at offset 8, removes
the low hash flag, and borrows bytes at offset 16. `memcpy` avoids private-struct
aliasing. No contents or lifetime are reconstructed from a pointer.

The original function/private length helper disassembly corroborates this layout;
native comparisons cover hash-cached/uncached strings, unique/retained references,
raw byte contents and actual parser/interpreter/slicing/serialization consumers.
The source-side hook traps the complete original body. Allocation observations
and a missing-release edit check the relevant ownership behavior. This is finite
experimental evidence with live, single-threaded objects and retained allocation,
release and interpreter services. It grants no stronger proof authority.
