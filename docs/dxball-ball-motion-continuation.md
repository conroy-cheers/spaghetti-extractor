# DX-Ball ball motion continuation — 2026-09-28

The [ball-motion component](../tests/fixtures/dxball-ball-motion/README.md) lifts
five native entries into 234 lines of ordinary C: creation, movement, paddle
rebound, brick contact and removal. The boundary borrows existing ball records,
sprite objects and the current board, and exposes allocation, audio, particles,
brick actions and life loss as services. Those helper bodies remain separate
work. Authoring used binary instructions/data and existing interfaces, without
original game source or changes to tool internals.

The first authored C matches all 29 local native cases unchanged. Cases cover
launch, walls, paddle zones, sticky/piercing balls, particles, directional brick
contact, allocation and removal, callback mutation and generated sequences.
Snapshots retain complete live ball payloads/links, cursors, allocation/free
identities, board bytes, sprite bytes and ordered interactions around callbacks.
Both native and C execution use controlled services and need no game startup.

Six small connected cases also match. The real gameplay frame calls the motion
component over the same objects for two frames per case. The scenarios include
launch, removal, brick contact and a service changing the current ball and sprite
bank. This checks caller/component interaction without launching the application
or implementing its graphics backend. Internal calls between the five motion
operations stay inside the component rather than becoming synthetic services.

The shared ball struct now uses the public opaque type tag so allocation/free
services can carry the existing record. Its fields, layout and frame behavior are
unchanged. All sixteen preceding frame cases pass after the refinement. Source
assembly explicitly acknowledges that header change; a first apply without the
frame acknowledgement was rejected before publication, with its preparation
retained. This was handled through the existing public workflow.

The standalone source project now has twenty-two components implementing 87
native entries and cumulative coverage of 288 source-consumer cases on x86-64
and AArch64. This continuation runs the new 29 direct and six connected cases and
rechecks the sixteen affected frame cases on both architectures. Unaffected
consumer evidence is reused. Twenty neighboring component records stay unchanged.
The three existing frame objects are recompiled because of the shared header;
the remaining 55 of 58 active prior objects are reused. All 58 prior objects
remain byte-identical. The archive change relinks consumers; that is not counted
as compilation reuse. The project is a portable subsystem project, not a complete
standalone DX-Ball.

## Integration as an additional check

The normal twenty-two-component network matches ball creation, launch and
sixteen gameplay frames, including shared state and pixel observations. The C
replacement is selected once for creation and sixteen times for movement.
Seventeen outer motion records retain ball and board contents. Forty-four input
observations retain the preceding paddle-only clock/random schedule. The ball
leaves its attached state and moves through free flight. Untouched original,
instrumented original and replacement processes all exit zero.

No behavioral correction to the first authored motion or frame C was needed
after local, connected, portable or normal execution. The live adapter registers
fresh allocation identities without interpreting their uninitialized links;
after creation, ordinary shared-state transport follows reachable objects around
services. This is target adapter work, not a new checker rule.

The sixteen-frame workload does not reach every brick, wall or special effect.
The local cases supply those scenarios directly. An end-to-end run must never be
the sole diagnostic route for a supported class of behavior: retain any finding
as a component, boundary or small connected regression, including shared memory,
aliases, lifetime, service order and environment inputs. If existing interfaces
and ordinary adapters cannot express or execute it, stop that lift and address
the tooling gap. Finite cases can still miss inputs; this rule is not a universal
equivalence claim.

The preceding [paddle discrepancy](dxball-gameplay-continuation.md) already
demonstrates this reduction: a native helper under either frame reproduces the
one-pixel drawing difference when random inputs differ and matches when they
correspond. This continuation adds connected allocation/motion coverage before
normal-game execution, using the same public facilities.

## Evidence and limits

Retained evidence is in `build/dxball-ball-motion-2026-09-28/`:

- `motion.asm`, `authored-first.json`, `prepared/` and `check/`: binary-derived
  authoring and the first-draft match for all 29 local cases.
- `prepared-final/`, `check-final/`: current local runtime with optional connected
  consumer support; only the adapter recompiles and all 29 cases match again.
- `frame-refined/`, `frame-check/`: shared type tag refinement and the sixteen
  affected parent cases.
- `connected-prepared/`, `connected-check/`: six two-frame local consumers.
- `normal-prepared/`, `normal-check/`: actual allocator/services and launched
  motion through normal execution, with the complete existing network selected.
- `program/`, `arm-program/`: public apply transactions and portable consumers.
  `validation.json`, `reuse.json` and `tree-audit.json` record exact evidence,
  reuse and preservation of unrelated dirty work.

Initial package preparation takes 0.395s, excluding manual boundary analysis and
adapter authoring. The first local comparison spends 0.278s compiling three
units, 0.064s linking, 4.074s in Wine startup wall time and 4.060s in 58 executions.
The connected check compiles five units in 0.342s, links in 0.064s, starts Wine in
4.591s and executes twelve runs in 0.968s. Normal integration compiles 45 units
in 1.737s, links in 0.064s, spends 61.957s in startup and 36.398s in three runs.
All comparisons perform zero model or solver work. Startup costs vary; the final
local adapter recheck spends 29.365s there despite compiling only one unit.

Successful allocations, finite acyclic traversed lists and live objects after
callbacks define the tested domain. Allocation failure preserves the original
exit path but is not covered by successful snapshots. Rebound preserves the
native binary32 ratio and binary64 intermediates under nearest rounding and
53-bit x87 precision. Paddle width must be nonzero; INT32_MIN angles are outside
the supplied trig view. The live observer has 64 encountered addresses per object
kind, 128 outer motion calls and 32 frames. It does not qualify unseen allocation
reuse inside a native helper.

The compiler-backed practical C profile accepts the implementation. The optional
formal profile reports allocation and volatile rounding constructs as unsupported; no strong
qualification is claimed. Repository metadata, production Python lint and format
registry checks accompany this work. All Wine runs use headless Wayland.
Remaining brick/effect/paddle services, scene entry/exit/input, startup and
portable platform backends still need lifting. No significant new tooling
limitation was found, and the full DX-Ball goal remains active.
