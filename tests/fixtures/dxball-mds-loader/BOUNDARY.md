# MDS file/memory loader boundary

Pinned DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`,
entry `0x401a20..0x401b60`. No original application source is used.

The caller supplies a writable output slot, an input view, length and flags.
Low flag bits 1 select a terminated filename; 2 select immutable memory; 0/3
return 4 without platform interaction. Higher bits are ignored. The existing
output value can be an opaque historical token. Success replaces it without
freeing it; every failure preserves it. Inputs and output are disjoint from
new allocations and each other; the output remains live through cleanup.

LocalAlloc flags 0x40 and size 36 are the original allocation contract. The
adapter maps its nine PE32 words onto the shared mds_info definition used by the
parser; native size does not define host pointer width. Allocation initializes
all words to zero, then the loader explicitly writes signature, stream and
pending count. Allocation failure returns 1.

File mode opens read/shared-read/existing, obtains the low 32-bit size, creates
a read-only mapping and maps the whole file. A failed size query is passed to
the parser unchanged. Failed open/mapping/view returns 2. File size and physical
readable backing are separate: every actual parser access must have storage under
the parser's existing boundary. Memory mode uses the supplied length and makes
no file/mapping calls. The parser is an independently lifted dependency, including
its partial writes, allocations, leaks and dangling buffer references.

Parser failure frees the info object before unmapping/closing the file resources;
success publishes it before those cleanup calls. Unmap, mapping close and file
close occur in that order. Cleanup results do not change the returned status or
publication. A failed free can leave the info allocation live. Mapped bytes are
not accessed after successful unmap; freed info is observed through a snapshot
captured while live. Buffers own their copied payload and survive unmapping.

Shared backend services execute the platform calls, track distinct handle,
storage and mapping lifetimes, and provide failure injection. Target transport
only supplies object layouts, identities and entry bindings. No service reentry
or concurrent actor mutates the output, info, filename or source bytes here.
The normal program supplies real loader callers and stream consumers. These
finite comparisons are experimental evidence, not a universal lifetime proof or
strong activation authority.
