# DX-Ball warning boundary investigation — 2026-09-28

The subsequent [warning continuation](dxball-warning-continuation.md) implements
the portable warning and checks historical-state transport. The sections below
retain the discovery sequence and the queue refinement that preceded it.

Local native execution found a hidden input before authoring the next warning
replacement. The last-brick warning reads old stack words if its board scan finds
no eligible cell. The [retained diagnostic](../tests/fixtures/dxball-warning/README.md)
reproduces this without game startup, using existing comparison infrastructure
and a small native entry adapter. No new tool internals were needed.

This is not merely a deliberately inconsistent remaining-brick counter. Starting
with tile byte 23 or 255, the original count returns one. The original hit clears
that cell without decrementing the retained count. The resulting board is empty
but the frame's `remaining_bricks == 1` guard still allows the warning call. The
board loader copies raw bytes without establishing a tile-range invariant. The
experiment executes count, hit and warning directly with controlled services;
whole-game reachability through loading, physics and frame dispatch is unverified.

Two runs with the same board and declared service inputs but different prior
stack contents produce different queue and explosion coordinates. The words
are at original warning-entry ESP -28 (y), -24 (row) and -20 (column and initial
x). A control with one eligible cell overwrites the words and gives identical
behavior for both seeds. Eight native cases exited successfully, with application
stderr empty. The retained review checks these relationships mechanically.

This establishes a boundary dependency, not a replacement mismatch: no authored
warning replacement exists yet. Scalar values, shared objects and memory views
can express the missing input, and native adapters can supply it for local
experiments. The missing work is identifying and preserving its producers across
the portable caller chain. Recompiling a caller does not preserve its former
physical stack contents. Merely capturing the new caller's stack or introducing
uninitialized C locals would not solve that correspondence.

Consequently, the existing finite frame and particle comparisons remain evidence
for their declared service scopes and cases. They do not establish composition
with a warning that observes prior private stack bytes. No implementation,
interface, source-project record or receipt was changed or promoted by the initial
diagnostic to cover this behavior. At that stage the source project had thirty-two components and
130 public entries, with 582 previously covered consumer cases; this diagnostic
adds no portable component or source-consumer coverage.

The subsequent producer experiment below traces the twelve-byte history through
the actual native frame. It narrows the provider requirement, while portable
transport remains outstanding. Do not build a general stack VM speculatively,
invent coordinate defaults, or assume a narrower board domain. Distinguish
manual boundary/adaptation work from missing workbench capabilities.

Evidence lives under `build/dxball-warning-2026-09-28/`: `warning.asm`,
`residue-probe/result.json`, per-case output/capture logs and
`residue-probe/review.json`. The initial probe took 4.828 seconds inside the
development/headless environment, including 0.214 seconds compiling/linking the
probe, 0.164 seconds compiling the capture launcher, 3.159 seconds of Wine startup
and 0.912 seconds executing eight cases. Shell/desktop setup is outside that
measurement. No model, solver, portable-source build or full-game run was needed.

The user's local-diagnosis requirement is met for this finding: whole-application
testing is not needed to reveal or reproduce it. Closing the semantic boundary
and delivering a portable warning are separate outstanding work. The full
DX-Ball goal stays active.

## Connected producer and alias investigation

Evidence under `build/dxball-warning-provenance-2026-09-28/` contains eight passing
`frame-probe/` cases and two passing `queue-probe/` cases. Both use the existing
native adapter/capture/session facilities under headless Wayland. The common
diagnostic runner now accepts explicit sources, hooks and case lists, avoiding a
second implementation of build, capture and lifecycle handling. Retained reviews
need neither compilation nor Wine. There are no new tool-internal changes.

The frame experiment keeps the actual frame, paddle, sprite, pickup, particle
and warning instruction bodies. It redirects the warning's existing call site
to an observer that copies the three words into diagnostic storage and jumps to
the original body at the unchanged stack pointer. It does not seed those words.
Unrelated helpers and platform services remain controlled. The frame's incoming
EBP/ESI are supplied explicitly, as any local native-entry context must be.

Native paddle drawing initializes all three relevant words on the reviewed
frame path: saved EBX supplies y (one), and the selected paddle sprite and vertical
offset supply row and column. Later ball drawing leaves saved EDI/ESI/EBP there;
pickup drawing, at a different stack depth, leaves ESI/EBP/EBX. Nonempty particle
drawing exposes surface descriptor words 20/21/22 at the same addresses. Empty
lists preserve the preceding producer. Partial service writes preserve the other
bytes. The cases verify each producer, precedence and partial descriptor writes.
Thus this path needs an explicit three-word compatibility state plus the relevant
incoming registers and service outputs, rather than an unexplained snapshot of
the entire preceding stack history.

Inspection of the normal direct call chain finds WinMain loading EBP from IAT
`0x415148` (DispatchMessageA) and ESI from `0x415164` (PeekMessageA), then calling
flow frame `0x40ab10` and gameplay frame `0x4044d0`. These two routines preserve
those values until the observed drawing calls. Two local cases supply the live
import addresses and confirm that they become queue coordinates. This establishes
the local register dependency; it is not full-game reachability or a promise that
the numeric addresses are stable across environments. A portable adapter must
carry the selected original-environment values explicitly, rather than cast its
own host function pointers or choose arbitrary defaults.

The queue consumer identifies a second concrete contract requirement. Paddle's
fixture state produces queue coordinate `(0,84)`, beyond the existing 20-by-20
domain. The actual queue calculates address `0x42d0f0` and reads a saved-board
byte. Changing that byte from zero to seven causes the original to allocate an
event and set the voice flag while the active board remains empty. The source
board-set layout places saved boards immediately after the active board, whereas
the native layout has intervening state. Extending C array indexing past the
active board would therefore have both undefined behavior and the wrong layout.
Rejecting every such access as a fault or returning zero would also be incorrect.

The next implementation work is a boundary refinement, using current facilities:

1. Define the three-word compatibility state and the original-environment register
   inputs once. Bind each producer's relevant effects in ordinary adapter C;
   preserve partial writes and the call ordering observed here.
2. Widen the queue's read boundary to an explicit original-address view with
   32-bit arithmetic and live aliases to current/saved boards and other admitted
   storage. Define access/fault outcomes; absence from an adapter's registrations
   alone does not prove that original memory was unmapped.
3. Compare the refined queue and warning locally and in the connected producer
   cases, then update affected source assemblies with accurate invalidation.
   Keep prior cases and neighboring component behavior intact.

The interface language already supports explicit context, services and byte
views; `component_local_bytes.py` supplies scoped storage, and
`candidate/runtime_memory_access.py` documents native admission predicates. The
latter explicitly is not a complete memory map: contents and handlers remain
caller responsibilities. Neither facility supplies the new compatibility backend
automatically. This investigation has not established a missing compiler/checker
rule or an inability to express the required adapter. It has established the
exact state and memory behavior that adapter must supply. If that implementation
requires a significant new tooling facility, stop and report the demonstrated
gap rather than inventing values or narrowing the target.

No portable warning component was added by these probes, no prior source component
or receipt changed, and no full-program execution was needed. These diagnostic
results are concrete native evidence, not replacement equivalence or strong
qualification. The subsequent queue refinement below adds replacement coverage.

## Queue read boundary refinement

The queue now requests its byte through the existing service interface. Its C
body does not index outside the active board. The service computes the original
32-bit wrapped address and resolves it to live current/saved-board or pending-byte
storage, or other explicitly admitted storage. This preserves aliases without
depending on the host objects having the old native layout. The existing nonlocal
service outcome mechanism represents a demonstrated memory fault; an unregistered
address remains an adapter capability error rather than an invented fault or zero.

Twenty-nine local native comparisons pass: the original twenty-one cases plus
eight exercising empty/nonempty saved-board reads, writes between successive
reads, wrapped address arithmetic, pending bytes, separately mapped storage,
the last saved-board byte and an explicitly protected page. The protected-page
case catches the original access violation at its actual byte-read instruction
and compares its address and unchanged state with the source's declared outcome.
It does not introduce an invalid C pointer access on portable hosts. The first
attempt could not reserve two occupied fixture addresses; moving those explicit
regions fixed setup without changing the queue implementation. The failed result
is retained, with no claimed match for the two unexecuted comparisons.

The four existing connected frame/motion/brick cases also pass. Applying the
refinement through `candidate apply` preserves all thirty-one neighboring
component records. On both x86-64 and AArch64, four affected objects are rebuilt
and 98 retain their bytes and mtimes. Thirty-six neighboring consumer binaries
remain byte-identical; the shared archive causes relinking, so their mtimes are
not claimed unchanged. The existing assembly recipe now replaces its own
Makefile section while retaining later consumers. Both the 29-case local and
four-case connected source consumers pass without Wine or the original image.
The project remains thirty-two components and 130 public entries, with 590
covered source-consumer cases. This refines an existing component rather than
adding one.

The latest normal network is revised in place, explicitly reviewing the incoming
`pickup-lifecycle/game-consumer` requirement and replacing the native read adapter.
Other implementations and the execution schedule are retained. Reusing its prior
comparison compiles four units rather than the preceding run's 63; model and
solver work remain zero. The 64-frame run matches all preceding observations.
It executes no queue call, so it supplies integration evidence, not coverage of
the expanded read behavior. That coverage comes from the independent consumers.

Evidence is under `build/dxball-queue-refinement-2026-09-28/`: `check/` retains the
setup failure, `check-v2/` the 29 matching cases, `connected-check/` the four
connected cases, `normal-check/` the normal comparison, and `program/` and
`arm-program/` the updated source projects. The fixture's
[`refine-queue.py`](../tests/fixtures/dxball-brick-actions/refine-queue.py) uses
existing package revision and service APIs; no tool internals changed. Preparation,
compiler, runtime and link timings remain separate in the retained receipts.

This completes the queue's reviewed read boundary for these environments. The
normal adapter still reads synchronized native address space; it is not a general
portable address-space backend. The warning's three-word compatibility provider
and a warning replacement remain outstanding. Queue preserves out-of-grid raw
coordinates in events, and their downstream consumption still needs its own
boundary refinement: this work does not authorize out-of-grid frame, hit or blast
accesses. No universal memory proof or full-game completion is claimed.
