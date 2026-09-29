# DX-Ball score-screen continuation — 2026-09-27

The [score-screen component](../tests/fixtures/dxball-score-scene/README.md) lifts
six real entries: enter, redraw, update, key dispatch, table rendering and name
editing. Its ordinary C reuses the menu's current score and scene/font/surface
objects, plus the persistent score table. Shared leave remains in the menu
component. Only executable instructions/data and retained assets were consulted;
no original game source or third-party implementation was used.

All twenty local native cases match. They exercise every new entry and the
existing table and font C, retaining full name/table/disk bytes, integer flags,
scene transitions, text spans/positions, timer/file interactions and pixel backing.
They cover qualification at the minimum, unsigned extremes, rejected insertion,
empty/full names, low-byte and ignored keys, exact Shift semantics, noncanonical
flags, timer wrap and inactivity, mouse clamping, highlight edges, file failures
and the retained real file. Selected original bodies remain trapped. The graphics
and file services in this consumer are controlled and explicitly scoped.

The C implementation needed no behavioral correction. Reusing the menu adapter
required a library guard instead of colliding nested `main` macros, a configurable
text-record capacity, and selecting the score-screen music track. The shared
line backend now handles vertical as well as horizontal lines. These are ordinary
C adapter changes, with existing consumers rechecked. No checker/compiler/artifact
internals or production APIs changed.

The public apply extends the source project to fifteen components and 51 native
entries. All eleven supplied build/integration commands pass, covering 171 cases
on x86-64. A clean AArch64 source build also passes all 171 cases through ten
consumer executables, each identified as AArch64 by its ELF header. The project
builds without lifting tools or the original executable; it remains a connected
subsystem project rather than a complete portable game.

All fourteen prior implementation, interface and contract identities remain
unchanged. Of 37 prior active objects, 35 remain byte-identical; the menu and scene
consumer adapters rebuild, and three screen objects are added. Thirteen generated
component README files update their comparison provenance; their code/contracts
are unchanged. This distinguishes neighboring implementation reuse from fresh
integration evidence.

Local preparation takes 0.427s, compilation 0.887s, link 0.064s, Wine startup
5.262s wall time, and forty executions 8.630s. The clean AArch64 build takes
46.091s and its ten check suites 50.835s. Manual boundary analysis and adapter
writing are separate costs. No model/solver work or large pilot rebuild was needed.

The live adapter installs all six entries with the existing game network. Both
consumer requirements are explicitly refined from controlled to actual game
services; merely adding a second table selection is correctly rejected. The
local twenty-case workload and the normal one-case workload need separate
comparison baselines. Passing the former as `--reuse-comparison` for the latter
is rejected because it drops retained cases; subsequent edits within either
workload can reuse that workload's compiled objects.

The retained normal workload now matches through title/menu/initial gameplay/
close: plain, original and source all exit zero with the fifteen-component network
installed. An earlier untouched-original run did not reach its first frame before
the controller deadline; an unchanged retry reused all 31 compiled units and
passed. The failed run is retained. This workload does not reach game over or the
score screen, so score-screen selection counts remain zero and no live score-screen
equivalence is claimed. A real game-over/name-entry
workload remains necessary as gameplay is lifted. Options, remaining gameplay,
startup and portable platform backends are also outstanding. The full DX-Ball
goal remains active; no significant tooling limitation was found in this work.

Evidence: `build/dxball-score-scene-2026-09-27/`.

- `scores-*.txt`, `name-edit.txt`: retained disassembly and literal-byte provenance.
- `prepared-2/`, `check-2/`: authored package and all twenty matching native cases.
- `check/`: the initial adapter macro collision and compiler feedback.
- `program.apply-dzm39bqd/`, `program/`: successful public apply and eleven checks.
- `arm-program/`, `arm-validation.json`, `arm-build.log`, `arm-check.log`: clean
  source build and all 171 cases on AArch64.
- `reuse.json`: prior identity/object reuse and provenance-only README differences.
- `normal-prepared-2/`: reviewed live requirements and installed game adapter.
- `normal-check-3/`: matching normal execution; all 31 compilation units reused,
  with zero screen calls explicitly retained as the remaining coverage gap.
- `normal-check-2/`: first retained normal baseline, with the untouched original
  failing to reach its first frame before the controller deadline; both observed
  executions exited zero. Wine diagnostics are separate from application output.

Every Wine execution uses headless Wayland. These are finite practical checks;
strong qualification and the full repository suite are not claimed.
