# DX-Ball music controller continuation

The application music controller now lifts into 44 lines of ordinary C through
existing interfaces, service bridges, original-body interception and source
assembly. The [recipe and boundary](../tests/fixtures/dxball-music/README.md)
cover play/replace (`0x402100`), resume (`0x4021a0`), pause (`0x4021d0`) and stop
(`0x402200`). The pinned original executable's instructions are the oracle; no
original application source was consulted and no tool internals changed.

The important behavior is shared ownership across calls. The native controller
reloads its current record after load, start, pause, stop and release services;
a callback can change which record is subsequently written or freed. It ignores
stop/release failures, frees the current record after start failure, and clears
the root even when a disposal callback changed it. Allocation failure is not
silently converted to an early return: the original still calls the loader and
can subsequently free null. The typed domain requires a live, nonnull record
where the original dereferences one; it does not claim arbitrary unsafe behavior.

## Delivered independent workflow

Evidence: `build/dxball-music-2026-09-29/`.

- `check`: all 30 independent original/C cases match the first implementation,
  including the four entries, error statuses, historical flags, callback root
  redirection and a play/pause/resume/stop sequence. No game startup or MIDI
  device is needed. These are application-library service scenarios, not
  target-specific WinMM emulation.
- `defect-check`: caching the record across resume writes the wrong object.
  The public local edit/check workflow finds the mismatch at
  `$.music.states[0][2]`; one unit recompiles and two are reused.
- `program` and `arm-program`: public `candidate apply` builds standalone source
  consumers and all 30 cases pass on x86-64 and emulated AArch64. All 39 prior
  component records, 127 existing compiled objects and 46 existing consumer
  binaries remain unchanged. The selection has 40 components, 156 public entries
  and 880 retained cases; only the new 30 cases required execution here.

Normal integration (`normal-check-v4`) also matches through 64 frames. All 38
preceding observation fields are identical to the preceding reader run. The new
music field records eight outer calls: one successful load/start, two resumes,
two pauses and three stops, with one allocated and freed record. All four entries
are reached. All four source controller bodies remain trapped; the MDS library below
continues executing natively. This adds consumer evidence without claiming MIDI
completion coverage from that normal workload.

Normal preparation exposed an allocator-observer conflict: the existing powerup
observer already owned the allocation entry. Its observation is now shared through
an optional callback, preserving the earlier registration behavior. The music
observer chains any prior callback instead of installing a competing hook. The
reader's report has the same observation/library-entry factoring as preceding
normal adapters, retaining every old field. The controller C did not change.
The recheck compiled one unit and reused 84.

Two comparison-reuse attempts were rejected before execution: the prior normal
receipt belonged to another component, and the local receipt had a different case
suite. The first new normal context therefore compiled its own inputs. This is a
setup/cache-reuse rough edge; it did not require changing the checker or weakening
the case-preservation guard. Later normal rechecks reused that context normally.

The initial local check compiled three units in 0.26 seconds, linked in 0.064
seconds and ran 60 candidate processes in 4.79 seconds. Paired Wine startup took
3.76 seconds wall time. No pilot rebuild, proof model or solver was involved.
Exact preparation, final integration and export costs belong to the retained
receipts and `validation.json`, not a performance guarantee.

Repository metadata, production Python lint and format-registry checks pass.
All Wine executions used the headless Wayland desktop. Unrelated dirty-tree
files are unchanged; the retained preservation audit binds them to the turn
baseline. No commit was made.

## Recorded shared-backend limitation

The shared extension is now implemented; see
[mapped storage and queued MIDI](shared-wine-test-environment.md#mapped-storage-and-queued-midi-2026-09-29)
and `build/shared-wine-streaming-2026-09-29/`. The inspection below records the
boundary that motivated it. The resumed goal requires continuing with independent
MDS lifting, rather than stopping at this resolved backend gap.

The lower MDS library remains native. Its load/parse/release entries are
`0x401a20`, `0x401b60` and `0x401e40`; stream start/pause/stop are `0x401ea0`,
`0x401fe0` and `0x402030`. Retained `music.asm`, `imports.txt` and
`streaming-gap.json` bind this inspection to the original image and current
shared backend. The limitation is executable platform support, not a new
controller C mismatch or a formal solver failure.

Two connected platform responsibilities are absent from the shared environment:

1. Mapped input and pinned storage. The loader creates/maps a file mapping, then
   unmaps and closes it. The parser allocates and locks movable global memory
   for headers and payloads; disposal recovers the allocation handle, unlocks
   and frees it. The environment's synchronous file-read API does not establish
   mapped-view contents, aliasing or these allocation/lock lifetimes.
2. Queued MIDI output and completion. The library opens a stream with a function
   callback at `0x4020c0`, prepares 64-byte PE32 headers, queues their buffers,
   and restarts/pauses/resets the stream. Completion reads the owner from the
   header's user field, may requeue the same header, or decrements the outstanding
   buffer count. Reset/unprepare/close interact with those retained buffers.
   Current callbacks are explicit synchronous reentry; there is no pending
   completion schedule or MIDI header ownership state. Cross-thread platform
   calls already stop with `concurrent platform calls require a scheduling backend`.

Microsoft's [stream-open contract](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-midistreamopen),
[buffer preparation](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-midioutprepareheader)
and [queued output](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-midistreamout)
confirm why immediate scalar return schedules alone are insufficient: headers,
data and callbacks participate in the operation's lifetime. The original also
calls midiStreamOut from its callback, which Microsoft warns can deadlock for
multimedia calls in [MidiOutProc](https://learn.microsoft.com/en-us/previous-versions/dd798478(v=vs.85)).
This is not a newly observed deadlock; a faithful lift must not silently repair
that interaction or declare it safe from a passing ordinary workload.

The next reusable facility should keep the existing candidate-neutral backend:
map/unmap and allocation/lock observations, prepared/queued/completed buffer
identities, explicit finite completion schedules, reset/close handling, and
native Wine call-through. An independent SDK/binding consumer should exercise
failure and completion/lifetime behavior before the target adapter supplies MDS
layouts and callback bodies. A pragmatic deterministic completion schedule is
useful; a universal concurrency proof is not a prerequisite for experimental use.

The preceding lifting attempt stopped at this shared platform boundary. Keeping the lower
library native makes the controller independently liftable, but does not complete
music playback or a portable DX-Ball. Adding DX-Ball-specific WinMM or mapping
mocks would repeat the ownership problem that the shared environment addresses.
