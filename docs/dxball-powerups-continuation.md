# DX-Ball powerup actions — 2026-09-28

The [powerup component](../tests/fixtures/dxball-powerups/README.md) lifts seven
entries into 145 lines of C: ball splitting, explosive-cell expansion, brick
softening, detonation, super balls, board dropping and attached-ball release.
Authoring used the pinned executable's instructions and data, without original
source or new tool internals. Thirteen services use existing shared object types.

The boundary exposes two actual native temporary lists alongside borrowed motion,
gameplay, board and graphics state. Splitting copies all ball payloads into a
temporary list, mirrors horizontal velocity, appends copies to the live list and
disposes of temporary records. Expansion queues existing explosive cells before
changing their neighbors. These lists reuse the existing ball/event layouts;
neighboring implementations and interfaces remain unchanged.

Thirty direct scenarios match the first C unchanged. They cover empty and
preexisting lists, allocation/disposal callbacks, attached-ball speed and counter
wrapping, cell scan order, graphics callbacks, hit results and complete action
sequences. Native softening performs successive checks of a cell, allowing a
callback to trigger another transformation in the same iteration. Board drop
passes the same mutable rectangle to both blit arguments; callback edits remain
visible in the final damage call. Both behaviors are observed locally.

Seven connected cases also match. Each runs four actual gameplay frames with
actual pickup collection and powerup bodies. Splitting turns three balls into
six through six allocations and three frees. Other cases exercise super balls,
explosive-cell expansion, softening, detonation and release. The paused case
preserves the pickup. Remaining movement, overlap, graphics and helper services
are controlled and observed. No full application startup is needed.

Public source applies pass on x86-64 and emulated AArch64. The source project now
contains twenty-nine components implementing 117 native entries, with cumulative
coverage of 485 source-consumer cases. This continuation runs thirty direct and
seven connected cases on each architecture and reuses unaffected evidence. All
twenty-eight neighboring component records, 86 prior compiled objects including
timestamps and thirty prior consumer binaries remain unchanged.

## Normal execution and diagnostic limits

The unchanged 64-frame launch/close comparison matches with all twenty-nine
components selected. All three processes exit zero, and preceding state, pixel,
palette and interaction observations remain compared. Seed, paddle environment
and 96 palette-clock inputs equal the preceding explosion run. There are no
dropped damage observations. The explosion observer was factored for inclusion;
the current comparison validates that factoring.

This workload reaches none of the seven powerup entries: `selected_powerups` is
`[0, 0, 0, 0, 0, 0, 0]`, with zero powerup observations. The match establishes
continued normal execution with the selection installed. Behavioral coverage
comes from the independent direct and connected consumers. Native allocator,
graphics and rebound services selected for powerups are not exercised by this
normal workload; neither are the allocation observer's active split/expansion
branches. Do not treat selection alone as evidence of execution.

The normal adapter follows reachable records from both live and temporary roots
through existing ball/event maps. It observes native transient allocations on
both sides so source-only inspection does not shift subsequent object identities.
Registration does not read uninitialized links. Observation retains 64 encountered
addresses per object type and 512 outer powerup calls. These bounds and lifetime
premises remain explicit comparison assumptions.

The integration setup initially used the wrong surface-observer helper name;
compilation caught it before execution. Assembly likewise caught a copied header
filename. Both were corrected in the adapter/recipe, with failed artifacts
retained. No behavioral correction to the lifted C was needed. Every semantic
integration finding must become a local or small connected regression; inability
to represent state, drive interactions or observe differences independently is a
tooling or boundary gap. A passing game rerun alone does not close one.

## Evidence and costs

Evidence is retained under `build/dxball-powerups-2026-09-28/`:

- `powerups.asm`, `authored-first.json`, `prepared/` and `check/` retain native
  instructions and the first thirty matching scenarios. `prepared-final/` and
  `check-final/` bind the final adapter with connected-consumer inclusion support.
- `frame-prepared/`, `frame-check/` and `connected-coverage.json` retain actual
  collection, shared state changes, temporary allocation and cleanup.
- `normal-prepared-v2/` and `normal-check-v2/` retain the final normal comparison
  and explicit evidence that the new entries were not reached.
- `program/`, `arm-program/` and their apply transactions retain portable builds,
  original x86 observations and reused neighboring records, objects and binaries.
- `validation.json`, `reuse.json`, `tree-audit.json` and `repository-gates.json`
  bind final fixtures, receipts, source applies and repository checks.

Package preparation takes 0.382s, excluding manual analysis and adapter authoring.
The final direct check reuses two objects, compiles one in 0.214s, links in 0.064s,
starts Wine in 4.316s wall time and executes sixty runs in 4.188s. Connected checking
compiles seven units in 0.455s, links in 0.064s, starts Wine in 26.145s and executes
fourteen runs in 1.096s. Source applies take 5.584s on x86-64 and 40.070s for the
cross build/run. Normal checking reuses two objects, compiles 57 units in 2.199s,
links in 0.064s, spends 52.606s in Wine startup wall time and 34.996s in three
executions. These are individual measurements; no model or solver work is done.

The supported domain requires live, finite, disjoint followed lists and valid
board coordinates. Services may mutate surviving objects; followed roots must
remain live. Returning controlled termination backends exercise allocation-failure
continuations without claiming actual process-exit coverage. Concrete comparisons
remain separate from strong qualification. Wine runs use a headless Wayland desktop.

Repository metadata, production Python lint and format registry checks accompany
this continuation. Scene lifecycle operations, startup and portable platform
backends remain open. The portable subsystem network is not yet a complete
standalone DX-Ball, and the full goal remains active.
