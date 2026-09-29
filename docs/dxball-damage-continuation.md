# DX-Ball damage and presentation continuation — 2026-09-28

The [damage component](../tests/fixtures/dxball-damage/README.md) lifts thirteen
actual native entries into ordinary C: queue reset, transparent/opaque tracked
sprites, marking, background erase, both-page damage, restoration, surface
selection, presentation, flushing, sorting and rectangle overlap. The existing
scene/title/font objects carry neighboring state; the component owns the two
page histories, pending rectangles, keys and timing state. Authoring used the
pinned executable and existing interfaces, without original DX-Ball sources or
changes to checker, compiler, artifact or proof machinery.

Nineteen local native scenarios match, with no game UI. They retain every queue
rectangle and key, object metadata, guards, complete final pixels and ordered
service calls. The source side traps all thirteen original bodies. Coverage
includes capacity, aliases, clipping, callback changes to page/count/rectangles,
appended work, exact flags, clock wrap, flip busy/lost/error paths and generated
geometry. Sprite dimensions are captured before drawing; restoration follows
the current page after callbacks. The C preserves the native selection-sort
order and signed wrapping overlap calculation, including inverted rectangles.

A public reopened workspace demonstrates a faulty local edit: keeping the
pre-callback rectangle instead of reading the newly selected page reports
`$.damage.states[2].pending[5][0]`, original 31 versus edited C 51. It rebuilds
one C unit and reuses eighteen. Restoring the original expression matches again.
The first observation draft retained queues as large byte strings; indexed
rectangle observations provide this useful field path while still comparing
all storage. This is ordinary observation authoring, without a diagnostic-engine
change.

The normal editor run exposed an observation bug before replacement execution:
damage reset can precede binding its software surface. The new live observer
attempted to hash that absent surface. The lifted C was unchanged. The boundary
now records that reset/setter states can have unbound surfaces, and the existing
local native transport preserves null handles. A shared observation helper
avoids pixel reads on absent surfaces. The local `unbound-reset` case exercises
the startup state, and removing that guard in a standalone consumer reproduces
the failure in 0.549s without Wine or the game UI. The regression therefore does
not depend on repeating the full editor run.

Normal execution now matches through the existing clear/save/close workload.
Untouched original, observed original and selected C all exit zero. There are
839 matching outer damage records, with no dropped records; reset, transparent
cursor, both-page damage, restore, surface selection and presentation execute
in C. Queue/key hashes, surface identities and selected pixel hashes accompany
the preceding editor/board/render observations. All sides save identical
20,000-byte `Default.bds` contents, clearing the first board and preserving the
other 49. Opaque drawing, erase, direct marking, geometry and flip-error paths
are covered locally rather than by this one live workload. Internal C helpers
do not need artificial calls through native entry hooks.

The source project now has nineteen components and 78 native entries. All
eighteen prior implementation/interface/contract identities remain unchanged;
48 of 49 prior compiled objects remain byte-identical. The shared title consumer
rebuilds after the null-handle adapter extension. All 228 x86-64 consumer cases
pass. The initial clean AArch64 build passed all 227 then-current cases; the
refined nineteen-case damage consumer and affected title consumer are rechecked
on AArch64, retaining the other unchanged consumer evidence. These are portable
subsystem consumers with controlled services, not yet a standalone complete game.

The final local comparison spends 0.249s preparing, 0.346s compiling two adapters,
0.064s linking, 4.563s in Wine startup wall time and 35.937s executing 38 runs with
full observations. The intentional callback edit compiles in 0.032s and executes
its pair in 0.381s; that run's Wine startup takes 56.095s. The successful live
recheck compiles two units in 0.447s, links in 0.064s, spends 57.868s on startup
and 47.619s executing three processes. Model and solver costs are zero. The final
x86-64 apply/build/check takes 24.527s. Manual analysis and adapter preparation
are not included in these command timings.

Several concurrent fresh Wine startups failed before cases could execute. Their
logs remain; serial rechecks succeeded. An initial reuse request also supplied
another component's receipt and was correctly rejected. Neither failed attempt
is counted as matching evidence. All Wine execution uses headless Wayland. No
large pilot rebuild or additional formal qualification campaign was performed.

Evidence root: `build/dxball-damage-2026-09-28/`.

- `prepared-4/`, `check-5/`: final nineteen-case native package and comparison.
- `check/`: initial adapter macro collision; `check-2/` and `check-3/`: matching
  eighteen-case predecessors and the improved indexed observations.
- `edit-2/`, `edit-wrong-2/`, `edit-corrected-2/`: local edit, discrepancy and repair.
- `observer-negative*`, `observer-regression.json`: the live observer failure
  reduced to the shared local startup observation, without Wine.
- `normal-check-2/`: retained unbound-surface observer failure;
  `normal-prepared-2/`, `normal-check-4/`: corrected matching live execution.
- `program/`, `program.apply-jweocmo7/`: final source project and fifteen passing
  build/consumer commands.
- `arm-program/`, `arm-validation.json`, `arm-observation-validation.json`,
  `arm-program.apply-4g77_u8k/`, `arm-title-recheck.log`: clean cross build and
  subsequent affected-consumer checks.
- `validation.json`, `tree-audit.json`, `nix-checks.log`: retained identities,
  costs, tree preservation and repository gates.

The delivery rule remains: reduce each semantic discrepancy found in whole-game
execution to a retained component, boundary or small connected regression.
Inability to express or execute it is a tooling gap; a missing input is a
coverage gap. This milestone demonstrates that rule with a real observation
failure, not a universal guarantee about undiscovered bugs. Region hit testing,
remaining gameplay, startup and portable graphics/audio/window backends still
need lifting. The full DX-Ball goal remains active.
