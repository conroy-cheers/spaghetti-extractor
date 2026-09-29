# Object allocation, destruction and copy-on-write

The selected operations own complete jq 1.8.1 object-table creation, destruction
and unsharing bodies in the pinned PE32 DLL (SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`).
Create is RVA `0x25f23..0x26021`, release `0x2a696..0x2a7e3`, and unshare
`0x2a7e3..0x2ab32`; retained symbol-table/disassembly inspection supplies the ranges.
Capacity is positive, a power of two, and its allocation fits the PE32 size domain.

Use the array subsystem's value holder and native descriptor layout. Holders
contain real pointers to live allocations; they do not reconstruct a heap from
integer tokens. Objects have positive reference counts, a bounded next-free
index, valid keys and values, and well-formed terminating bucket chains. Input
holders remain caller-owned; their contained reference is transferred exactly
once. Input and output holders may alias. Destruction requires an object holder.
The 8-byte header, 40-byte slots and 32-bit buckets are shared with unlifted jq
readers; changing them requires reviewing all those consumers.

Create initializes the entire table and returns its sole owner. Unshare returns
the same allocation when unique. For shared storage it preserves capacity,
next-free, slot positions, inactive slot bytes and buckets, retains active keys
and values, then releases the input object reference. Destruction decrements the
object count; on its final reference it releases active keys and values in slot
order, then disposes the table. Inactive values can contain stale bytes and must
never be released. Other owners' contents and reference counts are preserved.

The guarded allocator, generic value copy/release, scalar/string/array internals
and callbacks remain declared services. Native entry adapters alone express the
original private calling conventions. The portable bodies contain no Win32 ABI.
Nested objects are destroyed through the ordinary generic value dispatcher;
recursion is synchronous over live acyclic values. Intermediate instruction
counts, padding and diagnostic serialization allocations are unobserved.
Invalid/corrupt heaps, arbitrary reentrancy, concurrency and physical exhaustion
are outside this boundary. Nonlocal allocation failure is declared, not a
null-return promise. Finite comparisons are not universal lifetime proofs.
