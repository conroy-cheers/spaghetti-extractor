# DX-Ball WAV loading continuation

The WAV parser and loader now run as a connected component through the public
authoring, comparison and source-assembly workflow. The replacement is 69 lines
of C in [wave.c](../tests/fixtures/dxball-wave/wave.c), over the existing sound
bank and shared Wine/DirectSound backend. The original executable instructions
at `0x403000..0x403204` and `0x403470..0x4034ee` are the oracle. The descriptor
construction at `0x4034f0..0x403543` is expressed in the C loader. No original
application source was consulted and no tool internals were changed.

The [boundary and recipe](../tests/fixtures/dxball-wave/README.md) retain failure
behavior instead of repairing it: a failed load can leave a dangling slot; the
parser can publish data without writing a format pointer; failed metadata queries
can leave some or all incoming bytes untouched. Chunk padding wraps at uint32
width, duplicate formats replace prior outputs, and the first data chunk returns
immediately. Prior format state is a declared input captured from the native
entry frame. Readable extents, nonwrapping addresses, termination and live typed
accesses remain explicit premises.

Evidence is retained at `build/dxball-wave-lift-2026-09-28/`:

- `check`: all 52 original/C cases match on the first authored C. This includes
  parser outputs, allocation and file failure, positive creation/lock errors,
  disposal effects, partial query writes, callback redirection and a connected
  load/stop/release sequence. These cases do not start the game.
- `defect-check`: clearing the slot after failed file loading is rejected at
  `$.wave.final.roots[6]`. One C translation unit recompiles; seven are reused.
- `program` and `arm-program`: public `candidate apply` integrates the same C;
  all 52 cases match retained native observations on x86-64 and emulated AArch64.
  All 37 preceding component implementations and all 83 existing top-level build
  objects on each architecture are unchanged. The project now has 38 components,
  151 public entries and 828 covered consumer cases.
- `normal-check-v2`: original, uninstrumented and replacement normal runs match
  through 64 frames, including 26 WAV loads. The source-side loader, parser and
  descriptor helper cannot fall back to original bodies. No behavioral C change
  was needed after integration feedback.

The previous 36 normal observation fields remain represented. Thirty-five are
byte-for-byte identical, including the 354-call Wine platform trace. The audio
bank's internal buffer labels changed because allocation transport now creates
views before publication; a single bijection preserves all prior buffer identity
and alias relationships, and every other bank observation is unchanged. The
mapping is retained in `prior-observation-correspondence.json`; no observation is
dropped. New `wave_loads` observations include record allocation/free counts,
live/retired slots and before/after bank state.

Preparation took 0.47 seconds. The initial local check compiled eight translation
units in 0.79 seconds, linked in 0.064 seconds and ran 104 candidate processes in
11.59 seconds; paired Wine prefix startup took 7.95 seconds wall time. The defect
check recompiled one unit in 0.032 seconds. Normal integration compiled 78 units
in 3.55 seconds and linked in 0.064 seconds. No pilot rebuild, proof model or
solver was used. These are development timings, not performance guarantees.

Preparation still exposes some rough edges. An input named `result` conflicts
with the generated return-value identity; naming it `outputs` resolves that with
the existing API. Moving from local to normal composition also requires explicitly
selecting the existing bank's normal adapter, even when the supplied setup caller
already selects it. The normal adapter needed the existing library-entry pattern
to avoid nested `DllMain` macros. These were preparation corrections, not changes
to the lifted behavior or new checker rules.

## File boundary and the original shared environment gap

The following records the stopping point of this WAV experiment. The subsequent
[file-reader continuation](dxball-file-reader-continuation.md) implements the
shared file backend and lifts that reader; this is no longer an open blocker.

The next lower service is the native file reader at `0x40d9f0..0x40db13`. Its
body calls `CreateFileA`, `GetFileSize`, `ReadFile` and `CloseHandle`. It tries a
fallback path after open failure, allocates or uses a supplied buffer, ignores
the returned byte count, leaks the open handle on allocation/read failure, and
frees the destination on read failure even in the caller-supplied-buffer mode.
Those are application boundary requirements; neither leak cleanup nor always-
owned buffers may be silently substituted.

Real Wine already executes these APIs. The missing facility is reusable file
service scenarios and observations: handle identity/lifetime, path and flags,
requested/actual byte counts, touched buffer bytes, failed/short reads and output
preservation. At that point the shared backend exported DirectSound/COM and MessageBox
operations only. The generic import hook can redirect calls, but does not supply
file API semantics; resource tokens record instrumented references, not file
contents or Win32 effects. Existing `ReadFile` usage in process observation reads
the harness's pipes and is not a candidate file-service backend.

Continuing that service with bespoke DX-Ball Win32 emulation would repeat the
platform ownership problem the shared backend was introduced to fix. The lifting
attempt stops at this new shared-environment limitation. File paths, fallback
policy and buffer ownership belong to the component; executable file scenarios
and observations should extend the shared candidate-neutral environment. Real-
file success cases alone would not demonstrate the important failure behavior.
The disassembly and import bindings are retained in `file-reader.asm` and
`file-imports.json`. This is the first encounter with this new blocker, not
completion of the full DX-Ball goal.

Music, the native file reader and remaining runtime/platform functions are still
retained. Standalone component consumers do not constitute a standalone game;
practical comparisons, assumptions and formal qualification remain distinct.
