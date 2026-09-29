# DX-Ball title animation continuation — 2026-09-27

The [title-animation component](../tests/fixtures/dxball-title-animation/README.md)
lifts four real functions used by the title scene: scrolling text, wave blits,
wobbling strips and palette cycling. It composes with existing font/drawing
components and borrows the existing palette/flow layouts. Its readable message,
sine table and graphics backing have explicit lifetime and mutation boundaries.
Only the executable, disassembly and existing operator-authored interfaces were
used; no original DX-Ball source or new tool internals were needed.

The binary's numeric helper scales an integer sine table by exactly 1/1024,
multiplies by an integer and truncates. The admitted products are exact in the
original x87 significand, so the replacement uses int64 multiplication/division
without a floating-point runtime. It retains endpoint entry 360 for negative
multiples, signed phase tests, counter wrapping and the original truncation.
This is a derived implementation for this numeric boundary, not general x87
emulation or a claim about floating-point status flags.

All eighteen native cases match. Three rounds per case exercise full pixel
backing, overlapping scrolling, palette bytes, call order and shared state.
Cases include missing glyphs, alternate display surfaces, callbacks replacing
surface objects, signed phases and palette limits. The original graphics status
codes are deliberately nonzero in the controlled backend and remain ignored.
Palette subtraction wraps instead of saturating; the wider SetEntries count is
retained. The source side traps the four selected machine bodies.

The public apply transaction extends the source project to eleven components
implementing thirty native entries. All 107 connected cases pass on x86-64 and in
a clean AArch64 build under QEMU. All 25 prior active objects are reused, and all
ten neighboring implementations and interfaces are unchanged. An initial unused
helper warning in the reused fixture runtime was repaired locally; the next
check reused its two successful objects. Preparation and compiler fixes required
no changes to the checker, artifact system or compiler infrastructure.

Normal execution also matches. The selected C executes four scrolls, four wave
updates, one wobble and four palette cycles. All thirteen post-operation records
match, including visible back/display pixel hashes, palette hashes and animation
state. Existing frame, image, sprite and metric observations remain in place.
Untouched original, observed original and selected C all exit zero under the same
counted splash/menu/gameplay/close input protocol.

The live observer adds read locks on both instrumented sides and assumes
quiescent eight-bit surfaces. Hashes provide practical observations; neither they
nor the untouched-original output control establish complete observer
transparency or arbitrary frame/audio equivalence. Title scene entry/redraw/update
orchestration, other scene/gameplay bodies and portable platform backends remain
to be lifted. The full DX-Ball goal stays active, with no significant tooling
blocker found at this checkpoint.

Measured costs: preparation recipe 0.54s; matching local check preparation 0.12s,
compiler 0.57s, link 0.11s, Wine startup 5.77s wall time and 36 executions 5.96s.
The initial failed compile costs another 0.28s. The live check compiles 23 units
in 0.95s, links in 0.064s and spends 31.75s on three executions. The clean AArch64
build and 107 cases take 42.23s. Manual binary analysis/adapter authoring is separate
from these command timings. Model/solver work is zero; no pilot rebuild occurred.

Evidence: `build/dxball-title-animation-2026-09-27/`.

- `prepared-2/`, `check-2/`: public boundary authoring and eighteen matching native cases.
- `check/`: retained compiler warning and successful object reuse source.
- `program.apply-toodt8_q/`, `program/`: public apply receipt and seven passing integration commands.
- `arm-program/`, `arm-validation.json`: source-only AArch64 delivery and all workloads.
- `normal-prepared/`, `normal-check/`: actual game integration and separate Wine/host logs.
- `reuse.json`, `validation.json`, `tree-audit.json`: reuse, current-source binding and preservation audit.

All Wine runs use headless Wayland. Repository metadata, production Python lint
and format-registry checks are run; full repository testing and strong
qualification are not claimed by this practical continuation.
