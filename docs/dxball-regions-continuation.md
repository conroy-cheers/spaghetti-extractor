# DX-Ball region-table continuation — 2026-09-28

The [hit-region component](../tests/fixtures/dxball-regions/README.md) lifts three
native entries into ordinary C: reset, definition and hit testing. The executable's
direct callers serve the board editor. The component borrows the editor's count
word and 25 records through one view, reusing the existing record declaration.
It does not allocate storage or need neighboring component bodies. Authoring used
the pinned binary and existing interfaces, without original game source or new
checker, compiler, artifact or proof machinery.

Nine local native scenarios match without the game UI. Observations retain every
record, count, argument, result and guard after each operation. They cover the
editor's palette geometry, reset's extra cleared sentinel, wrapping count words,
signed inclusive coordinates, overlapping regions, arbitrary enable words,
inverted rectangles, mutations between calls and generated geometry. Reset
requests of 23 clear 25 records; hit testing selects the last matching active
record and ignores record zero. Capacity and lifetime remain explicit boundary
premises, not extra checks that silently change production behavior.

A public reopened workspace detects a deliberate local edit from last match to
first match. It reports `$.regions[6].result`, original 3 versus replacement 1,
with the arguments and complete table available. One C unit recompiles and two
adapters are reused. Restoring the assignment passes while reusing all three
compiled units. This failure needs no full application. The authored source
required no behavioral correction during either local or real-program checks.

The source project adds this component to the existing editor's service bindings.
The new nine direct cases and all sixteen existing editor cases pass on x86-64
and AArch64. The latter keep their previous native-derived expected observations;
the three region services now execute the checked component instead of their
controlled implementations. All nineteen neighboring implementation, interface
and contract identities remain unchanged. Of 52 prior objects, 51 remain
byte-identical; only the editor's consumer object changes. The other thirteen
consumer binaries remain byte-identical on each architecture, so their previous
212-case evidence is reused. The assembled network now has twenty components,
81 native entries and 237 covered source-consumer cases. It remains a portable
subsystem project, not a standalone complete game.

The separate normal editor clear/save/close check matches across untouched
original, instrumented original and selected C. All processes exit zero. It
retains 49 complete region observations, selecting reset once, definition 44
times and lookup four times. Existing board, editor, renderer and damage
observations also match. Every side saves the same 20,000-byte `Default.bds`,
clearing the first board and preserving the remaining 49. No end-to-end-only
semantic failure appeared in this continuation.

Preparation takes 0.283s after manual boundary analysis (manual effort is not
timed). The direct native check spends 0.011s preparing, 0.196s compiling three
units, 0.064s linking, 4.259s in Wine startup wall time and 1.151s executing 18
runs. It performs no model or solver work. Public source apply plus the two
affected checks takes 3.781s on x86-64 and 30.185s for AArch64 cross execution.
The new live network compiles 41 units in 1.609s and links in 0.064s; startup takes
65.999s and three program executions take 27.987s. These measured costs continue
to favor retained local cases over repeated full-game runs.

The operator guide now explicitly requires integration discoveries to become
local or small connected regressions, including observer and adapter bugs. New
inputs are coverage gaps; inability to express or execute their state and
interactions locally is a tooling gap. The preceding damage observer failure
already has such a regression, without Wine or game UI. Finite test suites cannot
guarantee that integration will never discover another case.

Retained evidence is under `build/dxball-regions-2026-09-28/`:

- `callers.json`, `prepared/`, `check/`: binary callers, public authoring inputs
  and direct native comparisons.
- `edit/`, `edit-wrong/`, `edit-corrected/`: local edit, diagnosis and repair.
- `program/`, `arm-program/`, `apply-time.json`, `apply-arm-time.json`: source
  integration and the two affected consumers on both architectures.
- `normal-prepared/`, `normal-check/`: real editor integration, full region
  observations and saved-file results.
- `validation.json`, `tree-audit.json`: exact receipt, source, reuse and tree
  checks; repository metadata, production Python lint and format registry pass.

All Wine runs use the headless Wayland runner. No large pilot was rebuilt and no
unrelated changes were altered. Full repository testing and strong qualification
are not claimed. Gameplay/physics, live score entry, startup and portable graphics,
audio/window backends remain open; the full DX-Ball goal remains active.
