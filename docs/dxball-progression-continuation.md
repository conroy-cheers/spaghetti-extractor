# DX-Ball gameplay progression — 2026-09-28

The [progression component](../tests/fixtures/dxball-progression/README.md) lifts
eight entries in 109 lines of ordinary C: score/life refresh and drawing, remaining
cell counting, next-board selection, life loss, game over, restart and deferred
round transitions. It was authored from the pinned executable instructions/data,
without the original game source. The first C remains unchanged after comparison
and normal execution; no tool internals or neighboring implementations changed.

The boundary reuses existing paddle, pickup, motion, gameplay, brick, palette,
scene and graphics objects. Four native words expose pending transition,
board-changed and last-brick warning state. The old pickup `next_life` member is
the score cache here; retaining its existing declaration avoids changing
neighboring interfaces. This is a semantic clarification backed by the executable,
not an inferred invariant about extra-life thresholds.

Thirty-three local scenarios match the actual original routines without game
startup. They compare complete controlled shared state, board/pending/palette
bytes, live ball payloads/links and ordered service calls/results. They cover
unsigned decimal score conversion, signed life comparisons, wrapping counters,
mutable rectangle and rendering callbacks, every cell byte, staged RGB grayscale,
preserved fourth palette bytes, cleanup ordering and restart. In particular,
restart positions the paddle using its old width before selecting the new sprite
width, and marks the current ball after the creation callback returns.

Five connected cases execute the actual gameplay frame and progression bodies
over shared objects: life loss/restart, level completion/restart, game over,
final-level completion and pausing. Each runs up to four frames, stopping on a
score-scene request. Controlled movement requests the actual life-loss entry;
creation, cleanup, board loading and remaining helpers remain explicit observed
services. This provides transition integration coverage without the full game UI.

A deliberately wrong C variant attaches the last ball instead of the current
ball after creation. Diagnostic `--case restart-callbacks` replay catches it
locally at `$.progression[6].state.balls[0][11]`: original attached value 1,
replacement value 77. The normal workload does not exercise this distinction.
The mutant is retained separately; the production C remains unchanged. The check
retains the baseline case set and selects one case explicitly rather than silently
discarding other admitted coverage.

Both consumers pass on x86-64 and emulated AArch64 through public `candidate apply`.
The source project has thirty components, 125 native entries and 523 cumulative
covered consumer cases. All twenty-nine neighboring component records, 90 prior
objects (hash and modification time) and 32 previous consumer binaries remain
unchanged on both architectures. Only the two new consumers were run after the
incremental build; unchanged consumer evidence is reused.

Normal launch/gameplay/close also matches for 64 frames across untouched original,
instrumented original and selected C. Source selection counts, in operation order
refresh/draw/count/next/lose/over/restart/advance, are `[64, 1, 0, 0, 0, 0, 1, 64]`.
There are 129 outer progression observations: one restart and 64 refresh/advance
pairs. Drawing occurs inside restart; nested operation observations are folded
into the outer record. The workload does not lose a life or complete a level;
those behaviors are covered independently by the local and frame consumers.
Every preceding observation remains equal to the prior normal run, including
state, pixels, palettes, seed, gameplay inputs and all 96 palette-clock inputs.
No damage observations were dropped. Wine diagnostics remain separate from
application output, and every Wine process ran under headless Wayland.

The implementation needed no behavioral correction. Preparation fixes were in
adapter compilation: conditional unused helpers, indentation and macro names
colliding with included adapters. An incorrectly added AArch64 `-static` flag
failed because the retained toolchain lacks static libc; restoring its existing
link mode passed. These failures occurred before running the affected consumers.

The final local check reused two compiler units and compiled one in 0.214 seconds;
33 original/source pairs used 4.424 seconds of execution time. The connected check
compiled three units and reused two; ten executions used 1.040 seconds. Source
apply, incremental build and the two affected checks took 4.732 seconds on x86-64
and 28.636 seconds with the emulated AArch64 toolchain. Normal selection compiled
59 units, reused two and linked once; execution used 37.150 seconds. Wine startup
wall phases were 15.929, 37.112 and 55.735 seconds respectively. These are individual
phase measurements, not a controlled speedup; no model or solver work was requested.

Evidence is retained under `build/dxball-progression-2026-09-28/`:

- `progression.asm`, `authored-first.json` and `prepared/` retain native evidence,
  first C identity and the public interface-first preparation.
- `check-v2/` and `frame-check-final/` retain passing independent comparisons.
- `defect-replay/` retains the local wrong-current-ball diagnostic and replay
  command; `defect-intent.json` describes the mutation.
- `normal-check-v2/` retains the actual-program comparison and coverage diagnostics.
- `program/`, `arm-program/`, apply receipts and `reuse.json` retain source export,
  affected checks and neighboring artifact reuse.
- `validation.json`, `tree-audit.json` and `repository-gates.json` record final
  artifact checks, preservation of unrelated work and repository validation.

Semantic integration findings must have a retained component, boundary or small
connected reproduction. Inability to represent or execute the relevant state or
interaction locally is a tooling gap; absent cases are coverage gaps. A successful
game rerun alone closes neither. Concrete tests do not establish a guarantee for
unseen behaviors, and these results grant no strong qualification.

Last-brick warning operations, gameplay scene lifecycle, typed list cleanup,
startup and portable platform backends remain open. The source project is a
connected set of portable consumers, not a complete standalone game. The full
DX-Ball lifting goal stays active.
