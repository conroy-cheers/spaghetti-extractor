# DX-Ball explosion lifecycle — 2026-09-28

The [explosion component](../tests/fixtures/dxball-explosions/README.md) lifts reset,
creation and drawing/expiry into 48 lines of C. Four services cover allocation,
disposal, termination and sprite drawing. Authoring used executable instructions
and data, without original game source or new tool internals.

The component borrows the gameplay frame's explosion current/first slots and owns
the tail and retained word. The frame copies/tests opaque effect identities;
the owner accesses concrete explosion records through those same root slots.
Ordinary pointer conversions preserve this relationship without changing any
neighboring interface, implementation or record tag. The native adapter transports
reachable payloads and links as well as identity at each service boundary.

Twenty-one direct native scenarios match the first authored C unchanged. They
cover reset with live orphaned records, append, signed/wrapping coordinate clamps,
allocation and termination callbacks, drawing, expiry at every list position,
skipped successors, graphics/free callbacks, signed frame wrap, a complete
lifecycle and caller changes to current. All controlled live records, roots,
links and ordered service arguments/results are observed. The initial adapter
had a C identifier collision between a sprite array and a function; renaming the
array fixed compilation before execution. Comparison feedback required no
behavioral correction to the C or adapters.

Four connected cases match over 26 actual gameplay frames each. They compose the
existing ball-motion and frame implementations with explosion creation/drawing
over shared state. Ball contact creates an explosion, and level advancement waits
until its 22 animation steps and disposal complete. With piercing enabled,
creation is suppressed and advancement is immediate. Three initially expired
records take two frames to dispose of because the native iterator skips a
successor after removal. Pausing preserves the records. Graphics, brick hits and
remaining helpers are controlled and observed; no game startup is needed.

Public source applies pass on x86-64 and emulated AArch64. The source project has
twenty-eight components implementing 110 native entries, with cumulative coverage
of 448 source-consumer cases. This continuation runs 21 direct and four connected
cases on each architecture and reuses unaffected evidence. All twenty-seven
neighboring component records, all 82 prior objects including timestamps and all
twenty-eight prior consumer binaries remain unchanged.

## Normal integration and coverage

The unchanged 64-frame launch/close workload matches with all twenty-eight
components selected. It invokes reset once and drawing 64 times, always with an
empty explosion list. The retained `selected_explosions` value is `[1, 0, 64]`,
and all 65 outer observations have empty object lists. Creation, allocation,
expiry and their effect on level advancement are independently covered by the
direct/connected consumers; this normal workload does not establish them.

All three processes exit zero. Prior shot, paddle, particle, pickup, brick,
gameplay, damage, pixel and palette observations remain compared, with no dropped
damage records. Seed, paddle environment and 96 palette-clock inputs equal the
preceding shot run. The shot observer was factored for inclusion, validated by
this comparison. No workload change or C behavioral correction was needed.

The normal adapter maps the preceding observer's opaque effect views to concrete
explosion views and back at boundaries, including payloads and links. It retains
64 encountered addresses and 512 outer observations. Native allocation and
termination remain selected, but this workload does not exercise allocation.
These adapters and bounds remain explicit comparison assumptions.

Full-game execution is supplementary. Every semantic integration finding must
become a retained local or small connected regression using the actual original
bodies and replacement. If existing facilities cannot represent the state, drive
the interaction or observe the difference, that is a tooling or boundary gap.
A previously untested input is a coverage gap. The [component workflow](component-workflow.md)
requires this reduction even when the subsequent full-game run passes; finite
comparisons do not guarantee discovery of every unseen defect.

## Evidence and costs

Evidence is retained under `build/dxball-explosions-2026-09-28/`:

- `explosions.asm`, `reset.asm`, root-reference disassembly, `authored-first.json`,
  `prepared-v2/` and `check-2/` bind native evidence, the first C and direct cases.
- `frame-prepared/`, `frame-check/` and `connected-coverage.json` retain shared-root
  interactions, complete animation/disposal and level-advance timing.
- `normal-prepared/` and `normal-check/` retain reset/empty-list integration,
  previous observations and unchanged input schedules.
- `program/`, `arm-program/` and their apply transactions retain portable builds,
  original x86 observations and unchanged neighboring component records/objects.
- `validation.json`, `reuse.json`, `tree-audit.json` and `repository-gates.json`
  bind current fixtures, receipts, source applies and repository checks.

Package preparation takes 0.310s, excluding manual analysis and adapter authoring.
After correcting the adapter identifier, the direct check reuses two objects,
compiles one in 0.164s, links in 0.064s, starts Wine in 3.990s wall time and executes
42 runs in 2.787s. The connected check compiles seven units in 0.455s, links in
0.064s, starts Wine in 4.112s and executes eight runs in 0.814s. Source applies
take 11.349s on x86-64 and 19.691s for the cross build/run. Normal comparison
compiles 57 units in 2.250s, links in 0.064s, spends 37.796s in Wine startup wall
time and 67.597s in three executions. These are individual run measurements;
no model or solver work is performed.

The declared domain requires live shared objects, finite followed lists, readable
allocation payloads and service callbacks that leave followed roots valid. Reset
does not free orphaned records. A returning controlled termination backend checks
the failure call and continuation with a valid current record; it does not claim
actual process-exit coverage. Concrete comparisons remain separate from strong
qualification. All Wine applications run in a headless Wayland desktop.

Repository metadata, production Python lint and format registry checks accompany
the work. Powerup and scene lifecycle services, startup and portable platform
backends remain open. This is a portable subsystem network; complete standalone
DX-Ball remains unfinished and the full goal stays active.
