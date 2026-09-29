# Object deletion with copy-on-write and a mutable table view

Own the complete consuming `jv_object_delete(jv, jv)` operation at RVA
`0x2b1e4..0x2b2e3` of the pinned PE32 jq 1.8.1 DLL, SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
The authored C owns bucket selection, collision-chain traversal, unlinking the
matched slot, slot release order and input-key release. Its implementation calls
neither original deletion entry nor private deletion loop. Copy-on-write remains
an explicit lower service, including native allocation/reference behavior.

- Consume an owned live object and an owned live string; return the owned object
  with that key removed, or unchanged contents when the key is absent. Other
  owners may retain the original object, keys and nested values. Shared object
  storage must be copied before mutation; a unique object keeps its allocation.
  Even an absent key passes through unsharing, as in the original.
- Reuse the lookup's `object-native.h` layout and `object-view.h` slot prefix.
  Tables are well formed, with positive power-of-two capacity, terminating
  collision chains, valid slots and allocation sizes fitting `size_t`. Twice
  capacity fits `uint32_t`. Corrupt heaps and arbitrary byte inputs are outside
  this boundary. Private stored value bytes are interpreted only by C adapters.
- The unshare service consumes one object reference, returns one live exclusive
  table owner and supplies a mutable borrowed view. It preserves capacity,
  buckets, slot order and references to live keys/values. The view belongs to
  the returned object, not the potentially released input allocation. It cannot
  survive resize, object release, return or reentrant mutation.
- Unlink only the matched chain entry, release its stored key, mark the key null,
  then release its stored value. Preserve next-free, other chains and other inactive
  slot data. The original leaves the freed value's bytes in the now-unused slot;
  this operation never interprets them again. Release the caller's key last.
- Hash/equality borrow keys through the lookup's reviewed adapters; hashing may
  populate a shared string cache. Calls are synchronous and single-threaded.
  Intermediate temporary reference counts and instruction counts are unobserved.
  Other aliases' contents and final reference/lifetime effects are observed.
- Native copy-on-write uses the private helper at RVA `0x2a7e3`, whose result
  pointer is in EAX and value argument is on the stack. The Windows adapter owns
  that pinned ABI; the standalone backend calls its corresponding C helper.
  Allocation failure, callbacks and concurrency are not exercised here. The
  service declares its nonlocal failure rather than promising unconditional
  return; finite successful comparisons do not establish failure equivalence.

Ordinary implementation edits use this boundary, the current source and the
shared driver. New layouts or ownership conventions require reviewing the views
and consumers together. Opaque declarations do not themselves prove memory
contents, lifetime or an exclusive owner; the adapters implement those premises.
