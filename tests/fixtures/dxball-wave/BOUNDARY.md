# WAV parser and sound sample loading

The oracle is DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Loading is `0x403000..0x403204`; RIFF traversal is `0x403470..0x4034ee`.
The descriptor helper `0x4034f0..0x403543` is expressed directly in the C loader:
it constructs the legacy 20-byte descriptor with flags `0xe2`. The platform
binding maps that descriptor to the shared DirectSound backend's SDK call.
No original application source is consulted.

The existing audio owner supplies the fifty slots, device, primary and sample
views. Allocation maps a 37-byte machine record to the shared C sample layout;
its incoming payload bytes and buffer word are explicit provider state. Freeing
a sample does not clear its slot or release its buffer. That dangling identity
remains observable. A record is not made live merely because a slot refers to it.
The local allocator retains backing storage to observe its configured disposal
effects; continued ordinary field access requires live storage at that point.

The parser preserves existing outputs unless an encountered chunk writes them.
It returns immediately on the first data chunk, even before a format chunk, and
accepts format sizes of fourteen bytes. Duplicate formats replace the prior
format pointer. Chunk lengths round up to an even byte count with uint32 wrap.
The output view represents three distinct writable output cells; aliasing those
cells with each other or the input bytes requires another boundary mapping.

Readable backing storage must cover the header and each traversed chunk header;
sample copies and format observations must have readable extents as well.
The declared RIFF extent need not equal the file length. Address arithmetic must
not wrap the original 32-bit address space, and traversal must terminate. These
are input premises, not added file-validation behavior. Unread or missing format
outputs are preserved: loader entry's prior format pointer at ESP minus four is
an explicit wave_history input, used if a data chunk precedes all format chunks.
Source C does not read its own uninitialized stack.

Slot indices are below fifty. The saved filename, including its terminator, fits
in the 33-byte sample payload and does not overlap that copy's destination.
Long names within that span intentionally overwrite provider metadata, as in
the original. Allocation failure terminates with code one; file, parser, buffer
creation and lock failures leave the published sample slot dangling. Nonzero
creation/lock statuses, including positive ones, are failures. Unlock and metadata
query statuses are ignored; failed/partial query writes retain incoming bytes.
Application callbacks can redirect shared slots at service boundaries; subsequent
accesses reload the same fields as the original instructions.

File loading, allocation/disposal and process exit are explicit application/runtime
services. DirectSound behavior, failure schedules, output writes, callback dispatch
and platform observations come from the shared Wine environment. Local comparisons
and standalone consumers establish finite tested behavior, not formal summaries,
arbitrary malformed-memory behavior or a complete portable game runtime.
