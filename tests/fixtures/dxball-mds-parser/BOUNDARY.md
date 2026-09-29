# MDS container parser boundary

The oracle is DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`,
entry `0x401b60..0x401d5d`. Its caller is `0x401afe`; compact event expansion
is the separately lifted `mds-events` operation at `0x401d60`. No original
application source is used.

The live info object contains signature, division, buffer capacity, format bits,
buffer collection, stream token, playback flags, buffer count and pending count.
The parser initially clears its buffer pointer, copies format metadata before
checking the data chunk, and copies count before allocating. Other fields are
preserved. Incoming buffer references may be stale: this operation overwrites
them without dereferencing or disposing of them. Repeated parsing can therefore
leak a previous allocation, and a failed parse can leave a dangling buffer pointer.

File bytes are immutable and disjoint from info and output allocations. The
declared input length is separate from readable backing extent. The original
format/data chunk bounds include bytes later subtracted for headers; the C keeps
those comparisons and unsigned arithmetic, rather than silently repairing them.
The backing must cover every actual read on the admitted path, including reads
beyond an incorrectly declared length. Malformed cases retain explicit backing
bytes. Pointer wraparound outside the supplied storage and faults require a
separate boundary. Unaligned byte data is supported.

Global allocation requests retain the original flags and modulo-32-bit byte
count, including the 64-byte PE32 header span. Allocation, lock, handle lookup,
unlock and free use the shared Wine environment. Handles are distinct from locked
storage. A failed allocation is still followed by lock(null). A failed lock can
leak a successful allocation. Cleanup makes two handle lookups, ignores unlock/
free failures and does not clear the published buffer pointer.

Portable C uses a collection of typed headers, each with a payload pointer and
the event descriptor shared with `mds-events`. The adapter relates that collection
to the original contiguous headers and payloads, without assuming a host pointer
has PE32 width. Successful locks must supply complete storage for the declared
count and capacity; current comparisons use the shared backend's bounded storage
profile. Zero-byte and wrapped-zero allocation requests can fail before any
header is accessed. Header data pointer, capacity, owner, flags and next pointer
are initialized before validating each block. Bytes-used is historical state until
copy or successful expansion publishes it. All other header bytes and unwritten
payload bytes retain allocator history.

Historical pointer words are opaque tokens until initialized or related to a
known object; their existence does not establish readable pointees. The transport
preserves these words and actual object identities, snapshots bytes while locked,
and keeps only retained observations after unlock/free. It does not read freed
native storage. No concurrent mutation or service reentry changes this info
object or header geometry during parsing. `mds-events` receives disjoint live
input and output extents under its own existing boundary.

Local comparisons observe return status, partial info updates, whole allocation
bytes (with explicit pointer correspondence), live/lock histories and every
platform call. Controlled storage retains disposed bytes for observation only;
it does not establish production access after disposal. Normal integration uses
the actual loader and subsequent MIDI consumer. These are practical finite
comparisons, not a checked universal heap summary or activation authority.
