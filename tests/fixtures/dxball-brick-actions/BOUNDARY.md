# Brick rules and effect lifecycle

The pinned PE32 has SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
This component owns reset at `0x405a70`, hit at `0x405c80`, effect iteration at
`0x406020`, blast creation/step at `0x406070`/`0x406140`, event queuing at
`0x406410`, and flash creation/step at `0x4064b0`/`0x4065e0`. Internal calls stay
within the component. Rendering, audio, debris/particles, allocation and board
selection are actual pre-existing services. The authoring source is executable
instructions/data and established interfaces; no original game source is used.

The board, pending-cell bytes, event list, counters and motion flags are borrowed
from the existing motion/frame state. Effects have eight payload words and two
links. Flash creation changes only the low tile byte of its tile word;
the remaining bytes are preserved. Blast creation does not initialize that word.
The frame's opaque effect references and this component's payload views refer to
the same native objects; ordinary adapter identity maps reconcile their cursors
at synchronous boundaries. They do not authorize reads of freed objects.

Tested allocations succeed and provide readable initial bytes for fields that
creation preserves. Allocation failure retains the native exit(1) path but is
outside those successful cases. Traversed lists are finite and acyclic, every
later-dereferenced object remains live across service calls. Hit/flash coordinates
retain their existing 20-by-20 domain. Queue and blast operations use the
original-address memory boundary described below. Callbacks may change counters, board bytes,
surfaces, live payloads and list cursors. Snapshots observe those changes and the
original's access order. Synchronous callbacks do not introduce concurrent writes.
Blast neighbor tests retain the original signed comparisons of wrapped
`row - 1`, `row + 1`, `column - 1` and `column + 1`. An out-of-grid center
does not imply that all neighbors are suppressed.

Queue and blast's `read_cell(state,column,row)` service reads exactly one unsigned byte at
`uint32_t(0x42ca60 + uint32_t(20*row) + column)` in the selected original address
space. This replaces the former C array access, without extending host indexing
outside an object. The service returns 0..255, performs no program-visible writes
or callbacks, and preserves live aliases to current/saved boards, pending bytes
and any other admitted readable storage. A demonstrated native access failure
has the declared nonlocal outcome `memory-fault`; an unknown mapping is an
adapter capability gap, not permission to invent zero or assert a native fault.
`write_cell(state,column,row,value)` writes the low byte at the same address.
`write_pending` writes at `uint32_t(0x42cc10 + 20*row + column)`; the frame's
`read_pending` reads that same logical byte. These services perform only the
addressed access, with no additional callbacks. Reads and writes share live
owners; a write must be visible through every alias and in later snapshots.
All other bytes are preserved. Wider memory is admitted only through a backend
that supplies its actual contents, permissions and lifetime.

Queue retains the raw coordinate words in its event. Blast creation sets the
pending byte using those words, but computes drawing positions with wrapping
32-bit multiplication. At destruction and expiry, it reconstructs coordinates
by interpreting the wrapped position-minus-origin as signed and dividing by
30/15, truncating toward zero. Initial and final pending writes can therefore
address different bytes. Do not repair this native behavior. Neighbor allocation
can change the center byte; the decrement decision reloads it after those calls.
Expiry reloads the current effect and its coordinates after drawing callbacks.

The local adapter supplies current/saved-board and pending-byte views, one
explicit readable external byte and a separately mapped mutable page for the
wrapped-coordinate case. A separately reserved PAGE_NOACCESS region
demonstrates the original queue's actual access-violation outcome; the controlled
consumer catches that native outcome, while the source adapter uses the existing
declared nonlocal service and C jump support. Observations retain fault address,
shared bytes, event payloads/links and allocation calls. Source views consult
the live owners on each access, including changes during callbacks. Normal
Win32 integration reads/writes synchronized native address space; the general
portable address-space backend remains separate unfinished work. The warning's
reviewed compatibility-state producer is documented in its own boundary. These declarations and finite comparisons
are not checked memory summaries or universal fault qualification.

The effect iterator advances again after unlinking, potentially skipping a node.
Explosion neighbors are queued in the original order, including duplicates from
different explosions. Signed counter comparisons use wrapping 32-bit arithmetic.
Elapsed effects restore the board or background before unlinking/freeing, while
rectangle and cursor changes made by callbacks remain visible to later work.

Local cases compare full initialized payloads, preserved allocation bytes, links,
lifetimes, grid bytes and service calls. Finite comparisons are practical evidence,
not strong heap proofs. Every integration finding must be reducible to a local or
small connected case; inability to express one is a tooling gap. Full DX-Ball
startup and platform delivery remain separate unfinished work.

The service inherited under the name `debris` at `0x406ef0` is a random pickup
generator that can also emit particles. Its body remains native in the normal
consumer. A separate small consumer runs that actual helper and its CRT random
generator under either brick implementation, observing inputs, particle calls,
allocation and pickup contents. Seeds 1 and 2 exercise creation and no creation.
Normal execution supplies an explicit clock input only while the native random
initializer runs; the generator's algorithm remains native. This input is part
of the comparison's declared environment, not a production behavior change.

The frame's palette elapsed/now boundary similarly receives explicit clock inputs
while retaining the actual native elapsed and palette-cycle helpers. A small
consumer checks both sides of paused/running deadlines and observes complete
palette bytes and `SetEntries` calls. Unequal inputs reproduce the palette
divergence locally. Other helper clocks and delay loops remain outside this
scoped schedule; the normal run continues comparing palette and pixel outputs.
