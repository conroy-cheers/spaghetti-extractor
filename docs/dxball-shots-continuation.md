# DX-Ball shot lifecycle — 2026-09-28

The [shot component](../tests/fixtures/dxball-shots/README.md) lifts movement,
pair firing and removal into 65 lines of C. Eight services cover allocation,
disposal, termination, randomness, brick hits, sound stopping, panning and playback.
Authoring used executable instructions/data and existing interfaces, without
original game source or new tool internals.

The existing gameplay shot records, list roots and counter remain shared with
the frame. Paddle width, piercing and impact velocity remain in motion state;
score, board and sprite banks also retain their existing owners. An opaque
allocation handle supplies backing storage for the existing record type. Ordinary
C converts the pointer without introducing another layout or changing neighboring
record tags/interfaces. Callback changes cross the existing service boundary.

Thirty direct native scenarios match the first authored C unchanged. They cover
pair append and nonzero retained payloads, signed binary64 placement, allocation
and sound callbacks, removal positions and null-counter wrapping, free callbacks,
movement, board/ceiling boundaries, piercing, score results, skipped successors,
random/hit callbacks, all random choices and bank aliases. A valid cross-row board
alias retains the native linear indexing. A 64-step case covers firing through
complete expiry. Allocation failure checks the termination call and continuation
with an explicitly returning backend and a live current object; it does not claim
actual process-exit coverage.

Four connected cases match over eight actual gameplay frames each. The firing
case allocates twelve records, removes five and invokes five controlled brick
hits. The piercing case allocates six and invokes eight hits without removal;
the paused case preserves its two records, and the expiry case disposes of three.
The frame's firing condition is count below six. Because firing appends a pair,
the count can reach seven after an odd number of removals; both implementations
do so in the first case. Shot drawing also runs through the actual frame, with
graphics and remaining helpers controlled and observed. No game startup is needed.

Public source applies pass on x86-64 and emulated AArch64. The source project has
twenty-seven components implementing 107 native entries, with cumulative coverage
of 423 source-consumer cases. This continuation runs thirty direct and four
connected cases on each architecture and reuses unaffected evidence. All twenty-six
neighboring component records, all 78 prior objects including timestamps and all
twenty-six prior consumer binaries remain unchanged. No behavioral correction to
the C, local adapter or connected adapter was needed after comparison feedback.

## Normal integration and coverage

The unchanged 64-frame launch/close workload matches with all twenty-seven
components selected. It invokes lifted shot movement 64 times with an empty list;
it does not fire or remove shots. The retained `selected_shots` value is
`[64, 0, 0]`, and all 64 outer observations have empty object lists. This verifies
normal-frame selection and shared-state integration for that path. Firing,
allocation, disposal and hits are exercised by the independent direct/connected
consumers, not established by this normal workload.

All three processes exit zero. Prior paddle, particle, pickup, brick, gameplay,
damage, pixel and palette observations remain compared, with no dropped damage
records. The seed, paddle environment and 96 palette-clock inputs equal the prior
paddle run. The paddle observer was factored for inclusion and is validated by
this comparison. No workload changes, semantic fixes or new tool internals were
needed. Full-game runs remain supplementary; any discovered discrepancy must
become a retained local or small connected regression.

## Evidence and costs

Evidence is retained under `build/dxball-shots-2026-09-28/`:

- `shots.asm`, `authored-first.json`, `prepared/` and `check/` bind executable
  evidence, the first C and thirty matching direct scenarios.
- `frame-prepared/`, `frame-check/` and `connected-coverage.json` retain the
  connected caller, interactions and count-threshold behavior.
- `normal-prepared/` and `normal-check/` retain normal integration with explicit
  empty-list coverage and unchanged input schedules.
- `program/`, `arm-program/` and their apply transactions retain portable builds,
  native-derived case observations and unchanged neighboring records/objects.
- `validation.json`, `reuse.json`, `tree-audit.json` and `repository-gates.json`
  bind current fixtures, receipts, source applies and repository checks.

Package preparation takes 0.342s, excluding manual analysis and adapter authoring.
The direct check compiles three units in 0.228s, links in 0.114s, starts Wine in
5.292s wall time and executes sixty runs in 3.936s. The connected check compiles
five units in 0.341s, links in 0.064s, starts Wine in 4.490s and executes eight runs
in 0.812s. Source applies take 22.170s on x86-64 and 19.489s for the cross build/run.
Normal comparison compiles 55 units in 2.153s, links in 0.064s, spends 45.510s in
Wine startup wall time and 29.789s in three executions. These are individual run
measurements; no model or solver work is performed.

The declared domain requires live shared objects, finite lists, valid sprite
slot 32, readable allocation payloads and in-bounds linear board reads. Allocation
returns storage suitable for the existing record; arbitrary allocator/lifetime
behavior is not strongly qualified. Normal observation retains 512 outer calls
and the prior 64-address shot pool. Practical comparisons and strong qualification
remain separate. All Wine applications run in a headless Wayland desktop.

Repository metadata, production Python lint and format registry checks accompany
the work. Explosion, powerup and scene lifecycle operations, startup and portable
platform backends remain open. The source project is a portable subsystem network,
not a complete standalone DX-Ball. The full goal stays active.
