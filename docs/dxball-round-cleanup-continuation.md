# DX-Ball round cleanup and departure — 2026-09-28

The [round-cleanup component](../tests/fixtures/dxball-round-cleanup/README.md)
lifts two public entries in 65 lines of C: clear gameplay objects and leave the
gameplay scene. Five private native removal bodies become typed private helpers;
all their direct callers in the pinned executable are inside clear. Authoring
used executable instructions/data without the original game source. The first
authored C remains unchanged after all comparisons. No tool internals or
neighboring implementations/interfaces changed.

The boundary borrows existing progression, powerup, particle and explosion state,
reusing seven record types across nine lists. Disposal proceeds from each current
cursor, which may be a head, middle, tail or null independently of first/last.
Unlinking precedes the free callback; the next iteration rereads shared state.
Callbacks can stop or redirect a list, extend a later list, or repopulate an
already processed list without causing that earlier phase to repeat. Counters
and retention words remain unchanged unless a callback changes them. Existing
brick/explosion projections are synchronized at component and service boundaries.

Twenty-eight local cases match the actual original operations without game
startup. They cover cursor positions, empty/single/multiple records, individual
object kinds, generated list layouts, callback mutations, repeated cleanup and
partial/full leave. Observations retain complete controlled payloads, links,
roots, counters, board/palette bytes and ordered service arguments/state changes.
The free service consumes a complete existing typed allocation through an opaque
storage pointer. Tests assume finite well-formed lists and terminating callbacks;
they do not establish behavior for arbitrary corrupted heap graphs.

Four connected cases execute the actual progression and cleanup bodies over
shared objects: two successive restarts, a preexisting score-scene request,
last-life game over, and a free callback that changes the caller's game-over
decision. Restart disposes objects from all nine lists, creates a new ball, then
disposes that ball on the next transition. Remaining platform and rendering
services are controlled and observed. These consumers run without full startup
or UI automation, and portable source consumers run without Wine.

Both consumers pass on x86-64 and emulated AArch64 through public `candidate apply`.
The source project now has thirty-one components, 127 public native entries and
555 cumulative covered consumer cases. All thirty neighboring component records,
94 prior objects (hash and modification time), and 34 previous consumer binaries
remain unchanged on both architectures. Only the two affected consumers were
run after incremental assembly; unchanged consumer evidence is reused.

Normal launch/gameplay/close matches for 64 frames across untouched original,
instrumented original and selected C. Every preceding state, pixel, palette and
input observation remains unchanged. **Neither cleanup entry is reached**:
`selected_round_cleanup` is `[0, 0]`, all seven `selected_round_frees` counts are
zero, and there are no outer cleanup records. This run checks installation and
preservation of the preceding workload; cleanup coverage comes from the local
and connected consumers. Wine diagnostics remain separate from application
output, and all Wine applications ran under headless Wayland.

The practical compiler profile accepts this C. The optional restricted proof
frontend flags the typed-helper macro and the `free` service syntax as unsupported.
No model/solver work was requested, and no strong qualification is claimed.
This frontend limitation does not prevent the executable component workflow.

Public package preparation took 0.324 seconds. The local comparison compiled
three units in 0.278 seconds, linked in 0.064 seconds and used 5.187 seconds for
56 original/source executions. Its Wine startup wall phase was 4.309 seconds.
The connected comparison compiled five units in 0.392 seconds, linked in 0.064
seconds and used 0.963 seconds for eight executions; startup wall time was 4.409
seconds. Source apply/build and both affected checks took 5.631 seconds on x86-64
and 28.415 seconds with the emulated AArch64 toolchain. Normal selection compiled
63 units in 2.477 seconds and linked in 0.064 seconds; its three executions used
32.592 seconds and Wine startup wall time was 41.008 seconds. These are individual
phase measurements, not a controlled speedup or a measurement of manual analysis.

Evidence is retained under `build/dxball-round-cleanup-2026-09-28/`:

- `native-text.asm`, `authored-first.json` and `prepared/` retain executable
  evidence, initial C identity and public preparation inputs.
- `check/` and `connected-check/` retain independent comparison receipts.
- `normal-check/` retains the normal workload and its explicit zero cleanup
  coverage diagnostics.
- `program/`, `arm-program/`, apply receipts and `reuse.json` retain source export,
  affected checks and neighboring artifact reuse.
- `validation.json`, `tree-audit.json` and `repository-gates.json` record final
  evidence checks, preservation of unrelated work and repository validation.

Semantic end-to-end discrepancies must become retained component, boundary or
small connected regressions. Missing cases are coverage gaps; inability to
represent, drive or observe the relevant state/interaction without the full
application is a tooling gap. A successful game rerun alone closes neither.
Earlier local wrong-current-ball and native random/clock reproductions remain
examples of this diagnostic path; no new semantic integration discrepancy
appeared in this continuation. Finite tests cannot guarantee that integration
will never reveal a new behavior.

Last-brick warning operations, remaining gameplay scene lifecycle, startup and
portable platform backends remain open. The source project contains connected
portable consumers, not a complete standalone game. The full lifting goal stays
active.
