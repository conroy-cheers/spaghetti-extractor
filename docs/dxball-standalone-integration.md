# DX-Ball source-program integration

The [September 29 delivery review](dxball-windows-lift-delivery.md) completes the
practical Windows lifting goal, with the source archive, final application-body
inventory and explicit history/failure limits. The checkpoints below retain
their original evidence scopes.

The September 29 source selection now also builds a normal-entry PE32 executable.
It connects the existing 49 components through owned C state, resource adapters
and ordinary Win32 SDK calls. Title, menu and gameplay execute without loading the
original application image. Earlier mixed comparisons and subsystem consumers
remain useful evidence; they do not establish whole-game equivalence for this new
assembly. The delivery target is the Windows source application, using its Windows
runtime dependencies and tested through Wine. Native non-Windows porting is outside
project scope, as clarified by the operator on September 29.

The later Windows scene workload now reaches the editor and score screen through
ordinary keyboard/mouse messages. For both the original and source candidates,
it clears and saves the first board, visits the next board and returns. All three
visible editor captures and the complete saved board file match. A second workload
clears the first two boards through that editor, then starts a game. Normal
progression enters the score screen, displays the table and returns to the menu.
Both score images and the complete board/score files match; 6,455 pixels differ
in the animated return-menu capture, in its moving dots and ball. These external
wall-clock workloads do not establish synchronized rendering equivalence.

The first score workload captured an in-progress fade and clicked again before
the transition settled. Longer waits in the same public action script exercise
the intended sequence. One original run was interrupted with status 143 before
producing a completion report; it is retained as incomplete, not a pass. The
subsequent original and source runs both execute all 37 actions and exit normally.
No application component or state-binding change was needed.

The source handoff copies the existing component export, generated bridges,
ordinary application adapters and 46 data assets, with no original image or
compiled artifacts. Public `candidate apply` prepares and builds it in a fresh
directory outside the repository, then runs the same score workload. Its 2.54s
cold build invokes only Make and MinGW-w64, with Python module search variables
removed from the compiler environment. All 49 component sources and their
evidence are retained. The archive includes `WINDOWS.md` and standard SHA256SUMS;
extracting and building it produces the same executable section bytes.

A delivery audit found the original embedded icon had been omitted. The existing
data-preparation recipe now retains the two non-executable resource payloads and
emits ordinary Windows resource source for `windres`. The resulting PE has the
same resource IDs, languages and bytes as the original. Resource-only application
reuses all preceding C objects and leaves every preceding executable section
unchanged. No checker, shared backend or artifact-authority format is added.

Evidence: `build/dxball-program-scenes-windows-2026-09-29/validation.json`, the
scene comparisons, both public apply receipts, `archive-build.json`, and
`dxball-windows-source.tar.gz`. This closes the concrete source packaging and
five-scene execution gaps. Untouched native status/scratch histories and unbound
unsafe addresses remain explicit fidelity gaps, not silently accepted defaults.

`make dxball.exe` statically links the compiler runtime and imports only platform
DLLs. The SDK bindings cover window/messages, clocks, DirectDraw, DirectSound and
WinMM; component implementations are unchanged. Buffered PCX input, sprite/WAV
storage and file-reader transport use standard C. Descriptor leases retain the
same SDK storage through describe/lock retries/unlock. MIDI headers are attached
to their owned info record; native opening, header preparation/queueing and cleanup
are exercised, but asynchronous callback/lifetime equivalence is not established.

The standalone MIDI follow-up now exercises callback completion, reset and
requeue through this exact SDK adapter and the existing exported stream C. A
small consumer found the same unconditional-writeback problem as the earlier
comparison transport: an unchanged C view overwrote a provider's changed queue
link or flags. Both original failures are retained. The repaired adapter compares
against the imported view, publishes only actual C changes, and obtains its
baseline from the same captured header. The initial SDK private-field bytes are
copied from the retained header span in the owned parser allocation.

Seven cases pass: controlled requeue/stop, the two provider-update reproductions,
failed open, and native Wine completion, reset and looping requeue. The native
cases deliver two, two and six completion callbacks respectively. The reset and
loop cases retain `MIDIERR_STILLPLAYING` from both immediate unprepare calls; the
original C ignores those errors and close returns the pending buffers. The checks
do not replace that behavior with retries or synthesize successful cleanup. The
shared backend does not need target knowledge or new rules. Allocation retirement
under failed reset/close and arbitrary simultaneous writes remain outside these
assembly cases; earlier controlled component evidence keeps its existing scope.

The public adapter-only apply runs the new SDK check and the normal game workload.
The latter reaches gameplay, removes a brick, scores 10 and exits zero. It selects
the stream C 28 times; counts depend on the actual workload and timing. All 49
component records, 647 exported component files and 50 component objects remain
unchanged. Only the MIDI adapter changes among the 120 preceding assembly/bridge/
backend objects; new diagnostic consumer objects are additional. Preparation,
assembly, compile/link, MIDI checks and normal desktop checks take approximately
0.40, 1.42, 2.26, 2.75 and 15.52 seconds respectively. No pilot rebuild or model/
solver work occurs. Evidence: `build/dxball-program-midi-2026-09-29/validation.json`,
`before/`, `win32-program/midi-sdk-check/` and the public apply receipt.

The public apply path builds and executes this program. A generic external driver
launches either candidate, posts normal messages, moves the cursor, and requests
normal close. It has no application addresses, names, memory hooks or candidate
roles. The retained source workload reaches 71 gameplay frames; the original
also exits normally. A longer source run launches the ball, removes one brick and
records 10 points. These are wall-clock integration workloads, not deterministic
state/pixel comparisons. GDI captures are black for both and cannot serve as
rendering evidence; compositor observation is now available as described below.
The source runtime directory contains only the newly built
candidate, generic driver, actions and assets, never the original executable.

The preceding public-apply workload ran 164 gameplay frames, removed a brick and
scored 10 points, with 45,807,480 bytes of instrumentation over 14.04 seconds.
The shared source-binding generator now supports optional program tracing while
comparison preparation remains traced. The adapter-only public apply rebuilds
separate program bridges and preserves the existing component consumers. Its
workload runs 193 gameplay frames, removes a brick and scores 10 points with
zero trace bytes. Frame counts are timing-dependent diagnostics, not a throughput
claim. Application diagnostics, transport and outcome checks remain enabled;
missing required service observations still report incomplete. All 49 component
records and implementations remain unchanged. Evidence:
`build/dxball-program-tracing-2026-09-29/validation.json`.

Binding regeneration now batches existing reader calls: assembly preparation
drops from 26.9 to 1.4 seconds while still matching the exact selected headers.
The final public apply takes 19.2 seconds including the desktop workload. Its
compile/link check takes 0.85 seconds; preceding component objects, traced bridge
sources and objects, and the component archive remain byte-identical.

The shared headless runner now supports `--capture` and the generic desktop driver
supports `snapshot NAME.png`. Actual compositor images show both candidates'
title and gameplay output, without image addresses, application hooks or changes
to any component. The final paused pair matches all 307,200 visible game pixels.
An earlier paused pair differs at 16,261 pixels, all within the eight palette
colours that continue cycling during pause. Both results are retained; normal
wall-clock screenshots do not constitute deterministic rendering qualification.
Win32 reports virtual 1024x640 client geometry while the visible game image lies
at compositor (32,32), size 640x480, so that comparison region is an explicit
operator selection. Full desktop images, raw reported geometry and capture
diagnostics are retained. No assembly or component algorithm change was needed.
Evidence: `build/dxball-program-observation-2026-09-29/validation.json` and
`paused-image-comparison.json` in that directory.

The shared environment regression renders a native X11 colour window and checks
its actual compositor pixels, without a Wine prefix or game. An existing terminal
check had interrupted after input echo, which can precede foreground job startup;
it now waits for that job to report readiness before sending Ctrl-C. The complete
headless environment check passes, including capture, transport and cleanup.

Cursor movement exposed a shared harness defect rather than a component defect:
Xwayland dereferenced a missing pointer seat in `xwl_cursor_warped_to`, crashing
both candidates. Adding Weston's `--fake-seat` fixes that exact workload. The
headless-environment check includes a small X11 warp/query regression. Driver
reports, candidate streams, instrumentation and Wine/compositor logs are retained
separately. No original source or new proof machinery was needed.

Evidence and recipes: `build/dxball-program-platform-2026-09-29/validation.json`
and the [assembly workflow](../tests/fixtures/dxball-standalone/README.md).
The following sections record the preceding incremental assembly work.

Program assembly has now begun. `program-state.c` owns the existing component
views, shared board/score/palette storage, linked-list roots and numeric tables.
The extracted initial data consists of named non-executable PE spans, with exact
image and span hashes; no image is loaded at runtime. Startup bindings call the
existing score, board, numeric and clock components directly. Standard C file
adapters retain ignored transfer counts and partial-read behavior.

The executable assembly check exercises score initialization/loading, board load
and selection, and numeric initialization through those bindings. The resulting
bytes match retained native startup observations on x86-64 and emulated AArch64.
It also checks that consumers share their owners and that a second program's
state remains independent. This is not the desktop entry or a graphics/audio
backend check. The public `candidate apply` path preserves all 49 component
implementations, records, objects and existing consumers; no new component or
workbench format is introduced. Evidence and recipes:
`build/dxball-program-state-2026-09-29/` and the
[assembly workflow](../tests/fixtures/dxball-standalone/README.md).

The scene assembly connects the original five-scene dispatch table to the
existing menu, gameplay, editor, score and title components, plus shared drawing,
text, palette, damage, board and region services. Score leave intentionally calls
menu leave. Including `libprogram-state.a` in the complete relocatable link now
initially resolved 157 declared service bindings, 136 more than startup assembly
alone. Gameplay, allocation and audio connections resolve another 194, and MDS
resource connections add 26, bringing the total to 377. The remaining host
symbols then comprised 143 service bindings, 46 observation hooks and 23 runtime/library
symbols (212 total; AArch64 has 209 owing to compiler/runtime differences).
No missing methods are replaced by stubs, and no
new component or checker machinery is needed. Link resolution alone does not
establish execution of the entire dispatcher or platform connections.

The state review also exposed duplicated boundary views of original cells:
shell control/menu input, shell shift/score-screen shift, and title/flow surface
roots. Shell is the single modifier writer; dispatch refreshes readers and
`dxball_program_event` refreshes them before and after window callbacks. Platform
backends must enter through that function, including synchronous reentry. It
preserves the original key-dispatch-before-modifier-write order. Title owns the
surface roots and republishes them to flow. These specific read views need no
component implementation change or general heap model.

The menu/title key operations declare no services and use their existing exported
C APIs directly. This keeps input-only calls independent of rendering/audio
bindings in the full comparison bridge. Twenty-four retained native key outcomes
match on x86-64 and emulated AArch64, including stale input views in both
directions and independent program instances. Startup comparisons still pass;
all 49 component records and implementations, 161 preceding objects and 56
subsystem binaries remain identical on each architecture. Evidence:
`build/dxball-program-scenes-2026-09-29/validation.json`. This check does not
exercise the full scene dispatcher or window-event backend.

Gameplay composition now connects frame, motion, brick, pickup, paddle, shot,
particle, explosion, powerup, progression and round consumers. The application
uses typed malloc/free allocations; successful payload bytes are not zero-filled
as an accidental behavior change. Brick owns its list, publishing opaque root
identities to frame. Audio owns device/primary identities; flow borrows the
primary and observes device presence. Sound service calls preserve the original
one-shot versus looping distinction.

The ownership executable follows the production progression -> round-cleanup ->
free path over 36 allocated nodes across two independent owners and nine list
families. It checks root removal, shared brick identities and retained words on
both architectures. Host address/undefined-behavior sanitizers and leak detection
also pass. This is executable assembly evidence, not just link resolution.

A call-target review caught one incorrect new binding: menu's 401350 had been
routed to the single-page 401200 operation. These share the same C parameter
types, so compilation and the earlier input/startup checks could not catch it.
The corrected menu binding records the mirrored page; score-screen still uses
401200. Fourteen route checks exercise both pages. Reintroducing the menu error
fails the local ownership check, without running the full game. Existing lifted
algorithms are unchanged. Evidence:
`build/dxball-program-gameplay-2026-09-29/validation.json`.

MDS resources now use owned C allocations instead of original process storage.
The music adapter loads into a typed record, the existing loader/parser/event
chain initializes its buffers, and each buffer retains the info owner. The info
also retains its program owner for eventual MIDI callbacks. Read-only asset
input uses stdio and a mapping lifetime independent of its file handles.

All six bundled music files match retained native observations through file and
memory loading: 12 cases, 376 buffers and 1,513,032 used event bytes. The memory
input is overwritten and freed before output is observed, and file mappings have
already been released by the loader. Header data/owner relationships and metadata
also match. Both x86-64 and emulated AArch64 pass, as do host ASan/UBSan/leak
checks. Public apply retains all 49 component records/implementations, 161 prior
objects and 56 subsystem binaries. Startup, input and ownership checks still pass.
Evidence: `build/dxball-program-resources-2026-09-29/validation.json`.

The stdio adapter covers immutable packaged assets, translating path separators
but not filename case or general Win32 sharing semantics. Native allocation
geometry that cannot fit the owned storage stops with an explicit diagnostic;
it needs a separate memory transport to preserve unchecked overflow behavior.
Malformed inputs, allocator failure/lifetime histories and untouched allocation
bytes are not covered by this assembly check. Storage cleanup is exercised
directly; MIDI device execution, stream release and callbacks still require the
platform connection. No original application source was consulted and no new
workbench mechanism was needed.

The cleanup call uses the selected clear implementation's actual free-only
service closure through its exported C API. Its interface conservatively allows
the larger leave service set too; this assembly path is validated against the
exact selected implementation and must be rechecked after edits. It is not a new
contract-compatibility rule or a claim that every service allowed by that interface
has been supplied to this partial consumer.

Resource lifetimes, unchecked historical-memory access and descriptor/status
history remain part of the full assembly obligation. Audio/WAV history operands
are explicit in the owner; their default values do not reproduce every native
failure or malformed-file input. Last-brick preparation now uses the reviewed
predecessor/descriptor frame-history projection. Unchecked board/pending reads
resolve live board, pending and saved board storage by original address,
retaining wrap/alias behavior. An address outside those bindings produces a
capability diagnostic, not a fabricated native fault or bounds-clamped value.
The first source-only frame/event run now passes; wider unsafe memory and failure
histories remain unqualified.
The owner constructor must not be mistaken for complete heap correspondence.

The [worklist](../tests/fixtures/dxball-standalone/README.md) now separates remaining
application bodies, source-program state ownership and service wiring, CRT
adaptation, and reusable platform backends. A relocatable link of all current
component and bridge objects succeeds without symbol collisions. Before the
program assembly library, after raster support,
its 581 unresolved symbols comprise 520 declared service binding symbols, 46 entry
observation hooks and 15 runtime/other symbols. This includes every exported
operation; it is not a reachability analysis or a count of missing algorithms.
Many bindings will route to already lifted neighboring components. Two of the
other symbols were existing post-call transport hooks (`game_exit`, `round_exit`),
now implemented as publication of the shared views. They are not process exits.
The rest are compiler/libc facilities, including compiler-generated `sincos`
resolved by ordinary libm. The census does not fabricate implementations.

Numeric support now adds eight complete C bodies: table initialization, word and
floating readers, projections and pan. Nine local cases match the first C
unchanged. The normal workload calls initialization once and pan twice, with all
46 prior fields, 64 frames and 766 platform interactions unchanged; the six
reader/projection bodies are inlined by existing consumers and covered locally.
Both source architectures pass all nine cases and retain all 47 preceding
component implementations and records. The selection contains 48 components,
188 entries and 1,162 retained cases. A true-pi/180 substitution is caught locally
at sine entry 90. Evidence: `build/dxball-math-raster-2026-09-29/validation.json`;
recipes: [numeric workflow](../tests/fixtures/dxball-math/README.md).

The line and region-fill helpers now use ordinary C through shared DirectDraw
surface services: descriptors, Lock/Unlock, fill, storage and lifetime, with
controlled outcomes and native call-through. Independent Windows SDK and portable
bindings exercise the same backend; it has no original/replacement role. The
target fixture supplies its boundary and surface identities without implementing
COM methods or fill behavior.

All 18 local cases match the first raster C unchanged. A strict-threshold defect
is diagnosed locally. Normal execution selects 242 line calls and one fill,
preserving all 46 preceding non-platform fields and 64 frames. The expanded
platform observation has 1,493 calls, including 727 DirectDraw calls. Stable
borrowed-surface identities come from named program roots, preserving aliases;
view-cache encounter order was insufficient. Ownership remains with the program.

Repeated full pixel snapshots initially exceeded the retained report limit.
Exact backward references and sparse patches reduce them without dropping bytes;
DirectSound payloads can also reference an exact range of a prior file read.
The final source report is 7,948,483 bytes under the unchanged 8 MiB limit, with
21,007,440 bytes of instrumentation in its separate channel. The final normal
check compiles two translation units and reuses 105. These changes correct
identity transport and shared observation storage; authored raster C is unchanged.

Both x86-64 and emulated AArch64 exports execute 18 raster cases and 279 affected
existing consumer cases. The selection has 49 components, 190 entries and 1,180
retained cases; all 48 preceding component implementations remain unchanged.
Evidence: `build/shared-wine-draw-2026-09-29/validation.json`; recipes:
[raster workflow](../tests/fixtures/dxball-raster/README.md). Program-owned state,
remaining bindings and production backends remain outstanding. The shared DirectDraw test
surface is explicitly scoped; it does not implement a complete graphics backend.

The first missing shared dependency is now closed: the five palette fade, shift,
rotation and RGB-update bodies are 69 lines of ordinary C using existing PCX
palette storage and flow state. All 31 local cases match the first implementation
unchanged. Cases preserve flag bytes, whole palettes, rotating-buffer guards,
service order and callback changes. A deliberately three-byte shift is diagnosed
locally despite its RGB results looking correct. No new workbench internals or
original application source were needed.

Normal execution reaches these operations 45 times through title, menu and
actual gameplay callers. All 64 frames, 766 existing platform interactions and
43 preceding observation fields remain identical. The new observation field
records arguments and before/after palette hashes. The check compiles three
translation units and reuses 94. A preparation error initially omitted the
retained backend sources and was caught at link time; the recipe now retains
them explicitly. There was no authored-C correction after either local or normal
execution.

Both x86-64 and emulated AArch64 exported palette consumers pass the 31 cases.
That source selection has 45 components, 169 entries and 1,077 retained cases. All preceding
44 component implementations and records are unchanged. Only the new palette
consumer is built; preceding objects and consumer binaries are retained exactly.
This is an incremental source-library update, not yet a whole-program assembly.

Evidence is under `build/dxball-standalone-2026-09-29/`: pinned disassembly,
`palette-check`, `palette-normal-check-v2`, `palette-defect-check`, the two public
apply receipts, `source-audit-v2/inventory.json` and `validation.json`. All Wine
applications run under headless Wayland. Repository metadata, production Python
lint and format-registry checks accompany the targeted executable checks.

First-frame initialization, initial palette creation and full-surface clearing
are now another 50 lines of ordinary C. The component borrows the existing
application, scene, flow and palette objects. Its 29 local cases preserve full
palette storage, resource publication on errors, ordered calls, callback changes,
nonlocal exit and unsigned refresh timing. The first implementation matches
unchanged. A deliberately over-wide palette clear is diagnosed at the local
boundary. Scores and board loading compose with their existing C bodies in the
normal consumer; clocks, seeding and actual platform methods remain services.

Normal execution reaches bootstrap once and clearing 15 more times. All 44
preceding observation fields, 64 frames and 766 platform interactions remain
identical. The new field records outer operations, state and palette/surface
hashes; absolute clock values remain diagnostics. The successful check compiles
three translation units and reuses 96. Local fixture exit handling initially
left its service trace open; the existing handler API fixes that. A macro-name
collision in the included normal adapters was caught at compile time. Neither
issue required an authored-C correction or a change to workbench internals or
the shared Wine backend.

The exported selection now has 46 components, 172 entries and 1,106 retained
cases. Both x86-64 and emulated AArch64 execute the 29 new cases. All 45 preceding
component implementations and records, their objects and consumer binaries
are reused unchanged. This remains an incremental source-library update.
The [bootstrap workflow](../tests/fixtures/dxball-bootstrap/README.md) documents
preparation, local editing/replay, normal execution and public `candidate apply`.
Evidence is under `build/dxball-bootstrap-2026-09-29/`, including `check-v2`,
`normal-check-v2`, `defect-check`, both apply receipts, `source-audit` and
`validation.json`. Preparation-script time excludes manual binary analysis and
adapter authoring; those are still the main work in establishing this boundary.

The clock, refresh-wait and random-state bodies are now ordinary C, preserving
the original low-word counter policy, incoming query-storage history, cached
divisor, wrapping comparisons, callbacks, shared generator and fault outcomes.
All 46 local cases match the first C unchanged. A deliberately substituted
modular-subtraction elapsed test is caught locally. Actual platform clocks and
vertical-blank calls remain explicit services.

Normal execution records 334 outer runtime operations, including 298 refresh
waits, and preserves all 45 prior observation fields, 64 frames and 766 platform
interactions. Clock polling exposed the shared capture's mixed instrumentation
and application-output budget. The launcher now streams reserved instrumentation
to its own bounded 64 MiB channel; this run retains 20,867,016 bytes, with no event
sampling or weakened protocol checks. Application streams keep their 8 MiB
limits, and Wine diagnostics remain separate. Older retained launchers and
comparisons preserve their original interpretation.

The run also exposed a MIDI transport race: separate reads for the C view and
its write baseline could turn a provider-owned link update into an apparent C
edit. A small local interleaving case reproduces the lost link. Capturing the
baseline from the same words as the view fixes it, and all 50 MDS cases pass.
This corrects an application-state adapter; the shared Wine platform behavior
and all authored component C remain unchanged. The final normal check compiles
one adapter and reuses 101 objects.

Both source architectures pass the 46 runtime cases and 133 affected MDS
consumer cases. The selection has 47 components, 180 entries and 1,153 retained
cases. All preceding 46 component implementations are unchanged. Four MDS
evidence records refresh with the new comparison; the other 42 remain identical.
Only the three MDS consumer objects rebuild for the corrected transport.
Evidence is under `build/dxball-runtime-2026-09-29/`: `check`, `defect-check`,
`provider-read-before`, `provider-read-check`, `normal-check-v4`, both pairs of
public apply receipts, `source-audit-v2` and `validation.json`. The
[runtime workflow](../tests/fixtures/dxball-runtime/README.md) retains the setup.
Preparation timings exclude manual disassembly and boundary/adapter authoring.

The reviewed application bodies are selected as C, and the Windows source handoff
executes all five scenes. The final delivery review reconciles source coverage
with the original application-body inventory and documents the status/scratch-
history and unsafe-address exits as fidelity limits. The practical Windows lift
is delivered; another desktop runtime and second-architecture execution are
outside scope. Broader equivalence is not inferred from these passing workloads.
