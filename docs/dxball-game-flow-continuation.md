# DX-Ball frame and scene continuation — 2026-09-27

The [game-flow component](../tests/fixtures/dxball-game-flow/README.md) replaces
eight native entries with ordinary C: frame update, key dispatch, scene entry,
scene exit, scene redraw, surface checks, surface recovery and shutdown. It uses
explicit shared state and synchronous scene/platform services. Recovery calls the
existing sprite restoration and loader, including their allocation and file
consumers. Inputs are the pinned PE, disassembly, existing operator-authored
interfaces and original asset files; no original DX-Ball source is used.

All 32 native cases match, including callback changes to the requested scene,
back surface and audio object. They preserve exact refresh/status tests, partial
recovery failure, clearing state after callbacks, invalid scene words and the
binary's unusual shutdown first-frame condition. The C side traps the selected
original entries. The original side runs those real bodies through controlled
ordinary C services; it does not substitute a separately written dispatcher.

The public `candidate apply` transaction extends the source project to nine
components implementing 23 native entries. All 69 source-consumer cases pass on
x86-64 and in a clean AArch64 build under QEMU. Eighteen of nineteen previous
active objects are reused. Only the lifecycle consumer is rebuilt to expose its
reusable adapter; all eight neighboring component implementations and interfaces
are byte-for-byte unchanged. The initial apply used the wrong Python interpreter
and was withheld for missing `pefile`; selecting the lifting interpreter resolved
that preparation issue without a tool change.

A public reopened workspace demonstrates a local C edit: clearing pending before
calling scene entry leaves the callback's new pending value behind. The checker
reports `$.flow.after_frame[3]`, original zero versus edited C nine. It recompiles
one unit and reuses sixteen. Restoring the original ordering matches again. This
is executable comparison reuse, not a claim of reused formal qualification.

Normal execution now selects the C frame controller alongside the sprite network.
The external input controller uses a hardware execution breakpoint at the original
main-loop call site, VA `40d110`, to count frames and post key/mouse/close messages.
It reads native readiness state without writing game code or data. This same
protocol drives untouched original, observed original and selected C.

The later [application-shell lift](dxball-application-continuation.md) replaces
WinMain itself. Its controller now counts the outer frame entry and waits for
that call's return, avoiding both a dependency on the removed call site and
double counting through original-body observation wrappers.

The first controller draft counted frame *entry* hits, accidentally counting both
the observer wrapper and its call to the original body. Its mismatch remains
retained. Counting the caller's frame invocation resolves that discrepancy. The
final probe also leaves unexpected application breakpoints unhandled and retains
Wine/host diagnostics separately from application output.

Two corrected runs match. The latest selects twelve C frame updates, one key
dispatch, three redraw entries and shutdown. Internal enter/leave/recovery calls
inside the C frame implementation are ordinary C calls; zero external entry
counters for those helpers do not imply that they were skipped. The connected
program also selects seven loader calls, one sprite capture, drawing, fonts and
cleanup. All three processes exit zero. Fourteen outer control records, 32 metric
records, 128 graphics records and eight lifecycle records match. The input schedule
reaches splash, menu and gameplay and closes after twelve frames, including six
game frames. The earlier extra splash glyph is no longer present under this
corresponding input schedule; no graphics records were filtered to obtain a pass.

This establishes a useful control-flow boundary and real consumer integration,
not full-game equivalence. The frame controller's services still contain native
scene implementations and platform initialization. Graphics/audio remain native
in live runs and controlled in portable consumers. Debugger pause time remains
visible to wall clocks, and the probe observes bounded calls rather than every
pixel/audio sample or an arbitrary playthrough. Recovery is covered by connected
local cases; the live workload does not lose surfaces. Complete game logic and
portable platform backends remain work toward the unchanged DX-Ball goal.
No significant core tooling limitation was encountered.

Measured local-check costs: preparation 0.21s, compiler 0.81s, link 0.065s, Wine
startup 6.05s wall time, 64 original/source executions 7.32s. Recipe preparation is
0.74s, excluding manual binary analysis and adapter authoring. The deliberate
one-unit edit spends 0.032s compiling, 0.064s linking and 0.23s executing its pair;
Wine startup costs 4.06s wall time. A later simultaneous Wine setup is slower, so
these are retained measurements rather than latency guarantees. Model and solver
work are zero. No pilot rebuild or new proof machinery was needed.

Evidence: `build/dxball-game-flow-2026-09-27/`.

- `prepared/`, `check/`: public authoring and 32 matching native cases.
- `edit/`, `edit-wrong/`, `edit-corrected/`: reopen/edit/diagnose/repair with local compilation reuse.
- `program.apply-kw6wv7dx/`, `program/`: successful application, prior project and all four workloads.
- `arm-program/`, `arm-build-2.log`, `arm-check.log`: source-only AArch64 build and 69 passing cases. The first static-link attempt lacked static libc; the normal target toolchain links and runs successfully.
- `normal-check/`: preserved incorrect frame-entry counting result.
- `normal-prepared-4/`, `normal-check-3/`: final frame-call-site controller, matching normal execution and separate host diagnostics.
- `reuse.json`, `validation.json`, `tree-audit.json`: object/source reuse, validation and unrelated-work preservation.

All Wine applications run under headless Wayland. Repository metadata, production
Python lint and format registry are checked; no full repository suite rerun or
strong qualification is claimed.
