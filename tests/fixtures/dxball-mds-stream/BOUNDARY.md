# MDS stream and lifetime boundary

Pinned DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
Entries: start `0x401ea0..0x401fe0`, pause `0x401fe0..0x402026`, stop
`0x402030..0x4020bb`, completion callback `0x4020c0..0x4020f6` and release
`0x401e40..0x401e9b`. No original application source is consulted.

The shared info and buffer collection are those of the independently lifted
loader and parser. The info object is live on entry; signature checks preserve
all state on rejection. A nonzero stream token corresponds to an observed open,
including failed open publication. Buffers contain live complete headers and
payloads, with fixed capacity/geometry while traversed. Count and buffer root
are captured after the relevant platform call, as in the original. Platform
services and completion callbacks may change flags and pending count; they do
not resize, replace or free these objects during a header traversal.

The callback's header view borrows one existing buffer, retaining its owner
identity. The backend retains the stable platform header, never the temporary
view descriptor. Messages other than MOM_DONE ignore the header and may pass
null. The original ignores stream, instance and secondary callback arguments;
the portable callback boundary exposes only message and header. MOM_DONE queues
again only while looping and not stopping. Failed requeue decrements pending,
including modulo-32-bit underflow. Successful initial queue increments pending
after the call; historical pending counts are not reset by start or stop.

Failed start cleans up only a newly opened/published nonzero stream. Resuming an
existing paused stream does not repeat preparation or clean up restart failure.
Stop sets the stopping flag before reset, clears it on reset failure, otherwise
ignores all unprepare/close results and clears stream and flags. Release ignores
stop failure, attempts buffer unlock/free, marks the info as DATA and frees it,
even if cleanup failed. These behaviors are preserved rather than repaired.

Shared WinMM/storage services own execution, failures, queue order, callbacks and
lifetime checks. Target adapters carry the original header layout, host-width
pointer correspondence and application observation. Source C uses typed objects
and explicit platform services, without target addresses. Controlled scenarios
serialize component work and callback delivery, including nested callbacks
inside reset/close and completion between top-level calls. They do not establish
behavior under arbitrary unsynchronized concurrent application accesses.

Local observations include return values, info/header history, payload bytes,
callback effects and every shared platform interaction. Freed storage is observed
through retained snapshots. The reset-failure/release case explicitly enables
the shared controlled retained-disposal experiment: queued storage is freed,
the violation stays observable and later API/callback access is rejected.
This does not supply semantics for dereferencing dead storage. Translated MIDI
headers bind their logical 64-byte extent to live allocation identity/offset,
so zero-payload headers retain the same disposal observation on wider hosts.
Normal execution uses the real music controller and
Wine environment. Finite execution evidence does not establish a universal heap
or concurrency proof and grants no strong activation authority.
