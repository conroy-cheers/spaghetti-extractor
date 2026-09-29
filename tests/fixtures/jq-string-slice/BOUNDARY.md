# String slice boundary

`run(value, start, end)` consumes one live string reference and produces a fresh
string or an invalid value with a message. The complete pinned native operation
is `jv_string_slice`, RVA `0x29e0a..0x2a145`. Actual shared contents are borrowed;
retaining a descriptor does not copy its allocation. The operation never changes
input bytes. Its output string does not alias the input, even for a full slice.

Indices are signed 32-bit numbers. The original first clamps them against the
**byte length**, then advances through codepoints. Higher path callers normalize
their own codepoint indices first. Embedded NUL and malformed UTF-8 are included.
Only bytes traversed to establish the selected interval are validated: an empty
prefix need not inspect a later invalid byte. The input has well-formed live
storage, with length at most `INT32_MAX`; corrupt pointers/headers are excluded.

| Service | Contract |
| --- | --- |
| `contents` | Borrow the existing owner, return its actual byte pointer and length through a call-local C view; no extra owned reference |
| `create` | Borrow the still-live owner, allocate/copy the selected byte range into a fresh native string; may deliver `nomem` |
| `release` | Consume the reference once, with actual reference/free effects |
| `empty` | Allocate the original's empty string with capacity 16; may deliver `nomem` |
| `invalid` | Allocate the original invalid-UTF-8 diagnostic; may deliver `nomem` |

The normal path constructs its result before releasing the input. An exhausted
start or malformed traversed input releases it **before** constructing the empty
or error result. A nonlocal allocation failure therefore leaves different native
reference state depending on the path. Only caller-owned references are cleaned
up after the real callback and `longjmp`; the fixture does not repair lost ones.

The shared `string-view.h` defines borrowed contents once. Its native adapter now
uses `string-storage.h` to read the reviewed live allocation directly, without
calling `jv_string_length_bytes`. This permits that lower operation to be lifted
using the same contents contract without recursion. Direct C reads require
the owner's continued lifetime. Generated token/interaction checks do not prove
that lifetime or a heap relation. Constructors, destruction and allocation remain
native lower services; arbitrary reentrancy, concurrency and returning allocation
handlers are unsupported. This finite comparison does not qualify a replacement.
