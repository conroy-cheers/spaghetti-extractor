# DX-Ball particle lifecycle — 2026-09-28

The [particle component](../tests/fixtures/dxball-particles/README.md) lifts three
actual entries into 88 lines of C: creation, movement/expiry and pixel drawing.
Its linked records use nine native payload words and portable pointers. Seven
services cover allocation, disposal, termination, surface description, locking,
unlocking and damage registration. Authoring used executable instructions/data
and existing interfaces, without original game source or new tool internals.

Twenty native local scenarios match. They cover creation limits, allocation and
free callbacks, signed/wrapping counters, gravity, expiry, skipped successors
after removal, lock retries, colors and changing current objects/destinations.
A forty-step case exercises creation, movement, drawing and complete expiry.
Observations retain all live payloads/links, root identities, service effects and
exact pixel changes against known initial bytes, including padding and guards.
The allocation-failure case checks the termination call with a controlled
returning backend; it does not claim actual process-exit coverage.

Four connected cases match over eight actual gameplay frames each: expiry,
edge removal, pausing and creation during a frame through a controlled helper.
The actual native or C frame calls the corresponding particle implementation;
other helpers remain controlled. These cases run without game startup or a
graphics backend, and the frame implementation/interface remains unchanged.

During normal-consumer preparation, native state mapping identified a distinction
between the software surface at `0x41c728` and font destination at `0x434960`.
The initial local fixture had represented the former through a surrogate font
view. The final boundary borrows a pointer to the existing software-surface slot,
which also preserves destination reassignment across callbacks. Connected cases
use distinct font and particle destinations. This refinement preceded full-game
execution; the creation, movement and drawing algorithms did not change.

Public source applies pass on x86-64 and emulated AArch64. The source project
contains twenty-five components implementing 102 native entries, with cumulative
coverage of 364 source-consumer cases. This continuation runs its twenty direct
and four connected cases on both architectures and reuses unaffected evidence.
All twenty-four neighboring component records, all 70 prior compiled objects
and all twenty-two prior consumer binaries remain unchanged. The pickup normal
observer was factored for inclusion without changing its observations or C body.

## Normal integration

The normal 64-frame launch/close workload matches with all three particle entries
selected in C. The lifted pickup creates eight particles; the lifted frame calls
particle movement and drawing 64 times each. All 136 outer particle observations
match, including complete live payloads/links and software-surface pixel hashes.
The preceding pickup, board, brick, motion, damage, pixel and palette observations
remain compared. All three processes exit zero, with 870 damage records and no
drops. The seed, paddle schedule and 96 palette-clock inputs remain unchanged.
The workload does not exhaust the new particles; local and connected consumers
independently cover expiry and removal.

Two harness failures remain retained: Wine prefix startup failed before the
first execution, and a later instrumented-original run reached all 64 frames but
hit the controller deadline after requesting close. Diagnostic tracing then
showed both programs completing with identical state. That diagnostic comparison
was correctly rejected because its debug messages changed application stderr.
The final untraced comparison passes without changing the C or normal adapter.
This establishes the passing workload, not a diagnosed cause or permanent fix
for the intermittent startup/close delays.

An attempted cache handoff from the unrelated local suite was correctly rejected
because it changed the admitted case set. Reuse from the retained program run
keeps all 51 compiled units. The shared surface reference was the only C change,
made before normal integration; no behavioral correction followed game feedback.

## Evidence, costs and limits

Evidence is retained under `build/dxball-particles-2026-09-28/`:

- `particle.asm`, `authored-first.json`, `check-2/` retain the first algorithm and
  passing native comparisons; `check/` retains an initial adapter-enum naming
  diagnostic, with eligible objects reused by the following check.
- `authored-final.json`, `prepared-final/`, `check-final/`,
  `frame-prepared-final/` and `frame-check-final/` bind the explicit shared-surface
  boundary and final matching direct/connected comparisons.
- `normal-prepared-2/` retains the normal adapter and unchanged launch/close,
  random seed, paddle and palette-clock inputs. `normal-bootstrap-failure.json`
  and `normal-check/` preserve the initial Wine startup failure. `normal-check-3/`
  retains the controller deadline, `normal-debug-check-2/` and
  `normal-diagnostic.json` retain diagnostic-only equality, and `normal-check-4/`
  contains the passing untraced program comparison.
- `program/`, `arm-program/` and their apply transactions retain portable
  assembly, source-consumer checks and exact neighboring records/object reuse.
- `validation.json`, `reuse.json`, `tree-audit.json` and `repository-gates.json`
  bind current fixtures, native receipts, source applies and repository checks.

Package preparation takes 0.319s, excluding manual boundary/adapter authoring.
The final direct comparison compiles three units in 0.228s, links in 0.064s,
spends 3.840s in Wine startup wall time and 2.709s in forty executions. The
connected comparison compiles three units in 0.278s, reuses two, links in 0.064s,
starts Wine in 4.710s and executes eight runs in 0.813s. Source applies take
42.465s on x86-64 and 24.284s for the cross build/run. The final normal comparison
reuses all 51 units, links in 0.064s, spends 64.894s in startup wall time and
43.460s in three executions. These final-run timings exclude the retained failed
and diagnostic attempts. No model or solver work is performed. Startup times
remain variable; summed concurrent startup work is separate from wall time.

The boundary admits finite acyclic lists, live objects after callbacks, readable
allocation payloads and eventually successful surface locks. Drawn pixels must
fit the leased image with nonnegative pitch and valid native address arithmetic.
Finite observations do not strongly qualify arbitrary heaps, lifetime changes or
unseen allocator reuse. Normal observation retains 256 encountered particle
addresses and 512 outer calls. Existing proof standards remain unchanged.

Every integration discrepancy must become an independently executable local or
small connected regression. Inability to represent the needed state/interactions
is a tooling gap; unseen inputs are a coverage gap. Full application execution
must remain supplementary to the component workflow.

Repository metadata, production Python lint and format registry checks accompany
the work. All Wine executions use a headless Wayland desktop.

Paddle, shot, powerup and scene lifecycle operations, startup and portable
platform backends still require lifting. This source project is a portable
subsystem network, not a complete standalone DX-Ball. The full goal stays active.
