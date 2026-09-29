# Sound bank control and lifetime boundary

Original: pinned DX-Ball PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
The nine entries are suspend `0x402f20`, release-all `0x402f90`, release-one
`0x402fb0`, play `0x403210`, loop `0x4032b0`, stop-all `0x403350`, stop
`0x403370`, restore `0x4033d0` and shutdown `0x403460`. Original bodies are
the comparison oracle. No original game source is consulted.

One shared owner supplies the fifty sample slots at `0x42c948`, device at
`0x42ca10` and primary buffer at `0x42ca14`. Each sample has a buffer reference
and 33 retained bytes: its saved name and original provider metadata. Buffer,
device and sample identities, alias relationships and lifetimes are distinct.
Release-one frees the currently selected record and clears its slot. Suspend
releases buffers and the device but preserves records and their bytes. Shutdown
releases records first. No implicit releases or repaired dangling references are
introduced. Other slots can continue referring to a released record; ordinary
typed dereferences require a live record at the point they execute.

Providers can synchronously redirect slots, buffers, primary or device. The C
reloads the same fields as the original after each interaction; clearing a slot
or primary after a callback overwrites that callback's replacement, as originally.
An aliased reference alone does not establish live contents. Slot indices must
be below fifty on paths that access a slot. Restore names must terminate within
the supplied record payload; the copy is made before load may dispose that record.
Arbitrary adjacent-memory strings/indices and concurrent mutation need a refined
byte-address boundary. No service writes into unpassed private caller storage.

Play skips zero-valued setting requests, recognizes exactly result 2 or
`0x88780096` as retry triggers, restores the whole bank, then retries once with
the current buffer. Status HRESULTs are ignored. Stop passes its original slot
number as the initial status word, so an unwritten output can still trigger
restore. Restore instead reuses one local status word across its loop. Its
initial value is an explicit `audio_history.restore_status` input corresponding
to restore entry ESP minus `0x104`; local original invocations seed that word
before the frame is reserved. Each nested restore invocation receives that
declared historical input. Source C never reads its own uninitialized stack.
Callers/backend assembly must supply the history or establish complete status
outputs before it can matter; a stable signature does not supply that evidence.

Sample loading, device creation, COM buffer operations and allocation remain
explicit services or neighboring lifting work. Local cases compare ordered calls,
all slot references, retained bytes, callback effects and provider lifetimes
without normal game startup or an audio device. A small sequence can cross all
nine entries over the same objects. These finite comparisons are practical
evidence, not checked heap summaries or formal qualification. Every semantic
end-to-end finding must remain reproducible locally; missing representation,
execution or observation is a boundary/tooling gap.
