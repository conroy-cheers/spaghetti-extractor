# DX-Ball gameplay scene — 2026-09-28

The [gameplay-scene component](../tests/fixtures/dxball-game-scene/README.md)
lifts entry, redraw and keyboard handling in 80 lines of C. The implementation
was authored from the pinned executable's instructions, dispatch tables and data,
without the original game source. Its first authored C remains unchanged after
local, connected, portable-source and normal-program comparisons. No new tool
internals or neighboring component implementations/interfaces were needed.

The boundary borrows existing progression and damage objects, including the same
scene, graphics, sprite, paddle and gameplay state. Existing bank counts/retention
words, cached score and input-ready fields are reused. The only newly exposed
scalar is the binary64 stereo direction used by sound panning. Entry loads assets
and 25 sound slots in order, resets selected state, loads a board, restarts the
round and sets damage surfaces. Callback changes remain visible between steps.

Redraw preserves the alias between its source and destination rectangles and
rereads pause/capability/presentation state at the actual native boundaries.
Any key resumes pause value 1; uppercase P pauses only value 0. Cheat keys use the
currently selected sprite bank. Music selection retains its random result across
the stop callback, including out-of-range results that stop without starting a
track. The stereo key multiplies the stored direction by -1.0.

Twenty-four local cases match actual native entries without game startup. They
cover both presentation modes, aliased surfaces, callback-driven decisions,
rectangle mutation, every input byte with cheats disabled and enabled, arbitrary-
key resume, nonboolean pause values, current-bank dimensions, unsigned width
doubling, every music choice and finite stereo-direction values. Observations
include shared state, live ball contents/links, board/palette bytes, sprite
metadata, ordered service arguments and rectangle aliasing.

Three connected cases use the actual progression implementation. Entry calls
restart, which dispatches scene redraw, which calls progression score drawing:
a real cycle of calls over the same objects. Further cases exercise pause/resume
and cheat changes followed by restart. Remaining board-loading, allocation and
platform services are controlled and observed. No whole-game startup or UI
automation is needed for these comparisons.

Public `candidate apply` adds both consumers to x86-64 and emulated AArch64 source
projects, and both pass. The project now has thirty-two components, 130 public
native entries and 582 cumulative covered consumer cases. All thirty-one previous
component records, 98 prior objects (hash and modification time) and 36 prior
consumer binaries remain unchanged on both architectures. Only the two new
consumers were run after incremental assembly. Their helper headers live under
`common/game-scene/`, preserving existing consumer headers and compiled artifacts.

Normal launch/gameplay/close also matches across untouched original, instrumented
original and selected C for 64 frames. Selection counts are `[1, 1, 0]` for entry,
redraw and key. The one outer observation contains entry and its nested redraw.
The workload does not exercise key handling; that coverage comes from independent
consumers. Every preceding state, pixel, palette and input observation remains
unchanged, and no damage records were dropped. All Wine applications ran under
headless Wayland with host diagnostics separated from application output.

Two preparation errors were caught before execution: the adapted assembly script
checked for its new consumer instead of the preceding cleanup consumer, and
generic helper macros collided with an included scene adapter. Correcting the
predecessor check and prefixing the new macros fixed them. No behavioral C
correction followed from any comparison or normal-game feedback.

The practical compiler profile is satisfied, including the immutable static
storage check. The optional restricted proof frontend reports static tables/text
as unsupported. No model/solver work was requested, and no strong qualification
is claimed. These are finite practical comparisons with explicit service and
representation assumptions.

Package preparation took 0.441 seconds. The local comparison compiled three
units in 0.278 seconds and linked in 0.064 seconds; its 48 executions used 4.329
seconds, with 25.846 seconds of Wine startup wall time. The connected comparison
compiled five units in 0.342 seconds and linked in 0.064 seconds; six executions
used 0.686 seconds, with 25.224 seconds of startup wall time. Successful source
apply/build/check took 4.643 seconds on x86-64 and 62.360 seconds with the emulated
AArch64 toolchain. Normal selection compiled 63 units and reused two, taking
2.656 seconds of compilation and 0.064 seconds of linking; executions used 36.550
seconds and Wine startup wall time was 67.745 seconds. These are individual
measurements, not a controlled speedup or a measure of manual preparation effort.

Evidence is retained under `build/dxball-game-scene-2026-09-28/`:

- `scene-enter.asm`, `scene-key.asm`, `authored-first.json` and `prepared/` retain
  the native evidence, first C identity and public preparation inputs.
- `check/` and `connected-check/` retain passing independent comparisons.
- `normal-check-v2/` retains actual-program comparison and coverage diagnostics;
  `normal-check/` and `setup-fixes.json` retain the earlier compiler failure.
- `program/`, `arm-program/`, apply receipts and `reuse.json` retain source export,
  incremental validation and neighboring artifact reuse.
- `validation.json`, `tree-audit.json` and `repository-gates.json` record final
  evidence checks, preservation of unrelated work and repository validation.

Every semantic integration discrepancy must remain reproducible locally or in
a small connected consumer. Inability to represent, drive or observe it without
the full application is a tooling gap; missing cases are coverage gaps. No new
semantic integration discrepancy appeared here. Finite tests do not guarantee
unseen behavior.

Last-brick warning display, remaining runtime helpers, startup and portable
platform backends remain open. The source project is still a set of connected
portable consumers, not a complete standalone game. The full DX-Ball lifting goal
stays active.
