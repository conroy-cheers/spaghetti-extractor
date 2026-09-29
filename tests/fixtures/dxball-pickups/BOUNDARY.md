# Pickup lifecycle

Pinned PE32 SHA256:
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
The component owns creation at `0x406ef0`, movement/collection at `0x407420`,
drawing at `0x407a40`, and removal at `0x407a90`. Switch tables at `0x4073d4`
and `0x4079f4` are part of the binary-derived behavior. No original source is used.

Each pickup has seven 32-bit payload words and next/previous links. The component
borrows the existing motion, play, menu, sprite and board views. Its count, lives,
extra-life threshold and paddle sprite are explicit shared words, rather than
copies of existing gameplay flags. Randomness, allocation, audio, particles,
collision, drawing and existing powerup helpers are synchronous services.

Successful allocations provide readable initial payload bytes. Traversed lists
are finite and acyclic; objects subsequently read remain live across callbacks.
Sprite slots belong to an admitted bank and refer to live metadata. Widths and
heights are ordinary positive game dimensions. Unsigned state preserves wrapping
32-bit arithmetic, signed branches and truncation toward zero. Callbacks may
change shared fields, live cursors, sprite metadata and lists; transport and
observations retain those mutations. They do not imply checked heap summaries.

Removal decrements count even when current is null. Iteration advances again
after removal and can skip a node. Creation draws its initial random choice even
when count later prevents allocation. Kinds 0 and 1 have a second random gate;
kind 14 is emitted as kind 10. All these behaviors are retained.

Local comparisons observe payloads, links, lifetime, shared words, sprite data
and ordered service interactions. Connected consumers exercise callers over the
same state without game startup. Every integration finding must remain locally
reproducible; inability to express it through existing interfaces and ordinary
adapters is a tooling gap. Finite cases are practical evidence, not qualification
of every allocation failure, callback lifetime or full game/platform behavior.
