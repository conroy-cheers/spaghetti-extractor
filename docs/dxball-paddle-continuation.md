# DX-Ball paddle movement and drawing — 2026-09-28

The [paddle component](../tests/fixtures/dxball-paddle/README.md) lifts two actual
entries into 57 lines of C. Eight services expose cursor movement, elapsed time,
current time, the platform clock, random selection, surface blitting, damage and
sprite drawing. Authoring used executable instructions/data and existing shared
interfaces, without original game source or new tool internals.

The boundary borrows the existing pickup/motion/gameplay/scene object chain.
Paddle width, sprite, coordinates, mouse input and powerup flags keep their
existing owners. Only five animation/spark words belong to the new component.
Sprite banks, aliases and the software-surface slot also retain their existing
representations. Callback changes are transported at each service boundary;
native caching and rereads remain visible in the C.

Twenty-one direct native scenarios match the first authored C unchanged. They
cover signed/wrapping clamping, windowed movement, animation, powerup combinations,
deadline equality, all random variants, binary64 rounding, bank aliases and
changes made by cursor, clock, random, graphics and damage callbacks. Observations
include all borrowed scalar state, sprite payloads, bank/surface identities and
ordered service arguments/results. A twelve-step case combines movement and
drawing. Controlled graphics services observe calls without requiring game startup.

Four connected cases execute eight frames each through the actual frame, pickup
and paddle implementations. Pickup collection grows, shrinks or minimizes the
shared paddle and calls movement again; the frame then draws the updated state.
The fourth case covers windowed movement without a pickup. Other helpers are
controlled. Neither neighboring implementation nor interface needed changes.

Both consumers pass through public source apply on x86-64 and emulated AArch64.
The source project contains twenty-six components implementing 104 native
entries, with cumulative coverage of 389 source-consumer cases. This continuation
runs its twenty-one direct and four connected cases on each architecture and
reuses unaffected evidence. All twenty-five neighboring component records, all
74 prior compiled objects (including timestamps) and all twenty-four prior
consumer binaries remain unchanged. The particle normal observer was factored
for inclusion; the new normal comparison validates that composition.

## Normal integration

The existing 64-frame launch/close workload matches with paddle movement and
drawing each selected in C 64 times. All 128 outer paddle observations match,
including shared state and software-surface pixel hashes after drawing. The
preceding particle, pickup, brick, frame, damage, palette and pixel observations
remain compared. All three processes exit zero and no damage records are dropped.
The preceding seed, paddle-input scope and 96 palette-clock inputs are retained.

The paddle selection wrapper takes over the existing helper's clock/random scope;
it does not change the workload or discard application observations. Native
cursor and DirectDraw calls remain real services, while sprite and damage calls
reach previously lifted components. No behavioral correction followed local,
connected, cross-architecture or normal-game feedback. The only initial failure
was a misleading-indentation compiler diagnostic in the handwritten local test
adapter; the C and bridge had already compiled and were reused after that fix.

## Evidence, costs and limits

Evidence is retained under `build/dxball-paddle-2026-09-28/`:

- `paddle.asm` and `authored-first.json` bind the executable evidence and first C.
- `prepared/`, `check/`, `prepared-v2/` and `check-2/` retain the adapter diagnostic,
  correction and matching direct comparisons with source/bridge object reuse.
- `frame-prepared/` and `frame-check/` retain the three-component consumer.
- `normal-prepared/` and `normal-check/` retain the matching normal workload.
- `program/`, `arm-program/` and their apply transactions retain portable builds,
  source-consumer results and unchanged neighboring records/objects.
- `validation.json`, `reuse.json`, `tree-audit.json` and `repository-gates.json`
  bind fixture hashes, native receipts, source applies and repository checks.

Package preparation takes 0.326s, excluding manual analysis and adapter authoring.
The passing direct check compiles one adapter in 0.164s, reuses the C and bridge,
links in 0.064s, starts Wine in 4.190s wall time and executes 42 runs in 4.698s.
The connected check compiles seven units in 0.455s, links in 0.064s, starts Wine
in 4.341s and executes eight runs in 2.134s. Source applies take 9.001s on x86-64
and 55.287s for the cross build/run. The normal check compiles 53 units in 2.041s,
links in 0.064s, spends 67.446s in Wine startup wall time and 47.167s in three
executions. These are individual run measurements; startup time remains variable.
No model or solver work is performed.

The boundary requires a live shared object chain, valid selected sprite slots,
a nonzero divisor and a representable signed quotient. Crop conversion follows
the target's nearest/53-bit floating mode and executable binary64 constants.
Graphics services retain responsibility for valid rectangles and surface lifetime.
Local controlled calls exercise values beyond the normal graphics workload;
matching them does not establish graphics safety for arbitrary rectangles.
Normal observation retains 256 outer paddle calls. Finite comparisons are
practical evidence, not strong qualification of all states or interactions.

Every semantic discrepancy found during integration must become a retained local
or small connected regression, including environmental inputs and adapter faults.
If existing facilities cannot express or execute that reproduction, it is a
tooling gap. Unseen inputs remain a coverage gap. This continuation needed no
game-only semantic fix; the component workflow remains usable without a runnable
whole target. All Wine executions use a headless Wayland desktop.

Repository metadata, production Python lint and format registry checks accompany
the work. Shot, powerup and scene lifecycle operations, startup and portable
platform backends remain open. The portable source project is a subsystem network,
not a complete standalone DX-Ball. The full goal stays active.
