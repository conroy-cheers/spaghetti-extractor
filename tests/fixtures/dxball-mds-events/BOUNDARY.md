# MDS event expansion boundary

Oracle: DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`,
entry `0x401d60..0x401e33`. The caller is the MDS parser at `0x401cef`.
The boundary and C are derived from that machine code and bundled binary music
assets; no original application source is used.

Input and output are live, distinct descriptor objects. Their first three PE32
words are a byte pointer, capacity and bytes used. The input uses bytes-used;
its capacity is not a bound checked by this operation. The output uses capacity;
its incoming bytes-used value is historical state. Portable C uses a typed
descriptor with a host pointer. Other native MIDI-header fields are untouched.

The admitted byte regions are disjoint from each other and both descriptors.
Input has readable storage for bytes-used; output has writable storage for
capacity. These extents remain live through the synchronous call. Either byte
pointer may be null when its extent is zero. Byte alignment is unrestricted.
No platform services, allocation, asynchronous callbacks or surrounding game
state participate in this operation. The real parser supplies disjoint mapped
input and allocated output. Aliased descriptors, overlapping bytes, invalid
lifetimes and unreadable/writable extents require another boundary, not guessed
pointer reconstruction.

Each compact event has a delta word and event word. Expansion inserts a zero
stream word between them. The event's high bit selects a long payload; its low
24 bits give payload size, rounded to four bytes including the existing padding.
The routine retains padding bytes verbatim. It neither interprets MIDI events nor
normalizes unused bits. Input size must be divisible by four, but a final delta
without an event is rejected only after writing that delta to the output.

Failure may leave a written delta, inserted stream word, event or preceding
events. It leaves output bytes-used unchanged. Success publishes the expanded
size, including zero for empty input. Input descriptors/bytes, destination
capacity and pointer, unrelated header fields and destination bytes beyond the
actual writes are preserved. Observations retain complete byte regions and
guards, descriptor fields and return values; they do not merely compare the
reported output prefix.

Finite original-versus-C comparisons include generated blocks, malformed blocks,
unaligned bytes, historical output lengths and every block in all six bundled
MDS assets. The original parser remains the normal-entry caller for this unit.
These checks support experimental replacement; they do not establish a complete
portable player or strong universal qualification.
