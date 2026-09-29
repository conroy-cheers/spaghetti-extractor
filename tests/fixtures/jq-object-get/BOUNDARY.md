# Object lookup over a live shared table

This component owns the complete consuming `jv_object_get(jv, jv)` operation in
the pinned PE32 jq 1.8.1 DLL (SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`,
RVA `0x2a3e5..0x2a559`). The replacement traps that entire entry body. Its C owns
bucket selection, collision-chain traversal, missing-key behavior, result copying
and input release. Native string hashing/equality and reference management remain
explicit lower services; the authored code never calls the native lookup helper.

- Inputs are one owned live object reference and one owned live string reference.
  Other callers may retain either allocation. A key may share a stored key's
  allocation, and returned values may share other live values. Return one owned
  value, or jq's invalid value for an absent key. Present JSON null is distinct.
- The table view borrows the real allocation. Object descriptors, slots, buckets
  and strings are well formed; capacity is a positive power of two; indices are
  `-1` or in range; chains terminate. Allocation sizes and pointer arithmetic fit
  `size_t`, and twice the capacity fits `uint32_t`. Corrupt heaps are unadmitted.
- The reviewed layout is defined once in `object-native.h`. Slot links and hashes
  are read with `memcpy`, not by type-punning the native allocation. Copying a
  descriptor does not preserve an object after its owner is released. The view
  must not escape the call; the result reference is acquired before input release.
- Calls are single-threaded and synchronous, without concurrent table mutation,
  resize or reentrant callbacks. Other operations may update, delete, grow or
  copy-on-write the object between calls; every call obtains a fresh view.
- Hashing may populate the shared key's hash cache. The public hash/equality
  adapters temporarily copy and release references; their net reference effects
  match borrowed native helpers within this scope. Intermediate reference counts,
  instruction counts and asynchronous inspection are not observations. Byte
  contents, table shape and live aliases must otherwise be preserved by lookup.
- Direct cases observe result validity/content, retained input content/reference
  counts and allocator lifetime through cleanup. Interpreter cases exercise reads
  around updates/deletion through real callers. These are finite comparisons;
  opaque declarations and generated resource checks do not prove the heap view,
  all lifetimes, arbitrary failures, callbacks or concurrency.

Manual preparation included inspecting the private lookup loop and its callers,
the public entry ABI and shared object layout. Choosing the complete operation
keeps the existing production API and lets the same adapters work in the portable
source backend. No compiler, checker or artifact extensions are required.
