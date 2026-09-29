# DX-Ball brick rules and effects

[brick.c](brick.c) lifts eight actual operations: reset, hit, effect iteration,
blast creation/advance, event queuing and flash creation/advance. The component
uses the existing motion/frame board, pending-cell bytes, events and counters.
Its effect records retain payloads, links and partial-byte initialization.
[BOUNDARY.md](BOUNDARY.md) describes aliases, lifetime and admitted inputs.
Authoring used the executable and existing interfaces, without original sources.

Prepare from the preceding motion comparison:

```sh
python tests/fixtures/dxball-brick-actions/prepare.py \
  /path/to/DXBall.exe /tmp/dx-motion-check/inputs /tmp/dx-bricks
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-bricks/brick-actions --output /tmp/dx-bricks-check
```

Twenty-one original scenarios exercise all valid tile kinds, invalid bytes, piercing,
particles, callbacks, queued neighbors, delayed animation, unlink/free ordering,
unknown effects and generated sequences. Calls into original code use local
storage and controlled services, without game startup. Every live payload and
link, allocation identity, board/pending byte and ordered service interaction is
observed. The initial bytes deliberately supplied by the local allocator also
check partial initialization and preservation.

Eight further scenarios cover queue reads through live saved-board/pending aliases,
32-bit address wrapping, separately mapped storage and a deliberately inaccessible
page. The lifted queue uses `read_cell` instead of out-of-bounds C indexing.
The original accesses the actual native byte; the portable adapter reads its live
owner or reports the demonstrated nonlocal fault. Unknown mappings are adapter
errors, not invented zeros or faults. These cases run without game startup.

Refine a retained comparison without preparing the original image again:

```sh
python tests/fixtures/dxball-brick-actions/refine-queue.py \
  /tmp/dx-bricks-check/inputs /tmp/dx-queue-refined
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-queue-refined/package --output /tmp/dx-queue-check
```

`--keep-consumer` preserves a retained connected brick consumer and its cases.
`--normal-consumer` revises the brick supplier in the later normal gameplay
network, explicitly reviewing `pickup-lifecycle/game-consumer` and retaining all
other selections. The latter supplies native address reads, not a complete
portable memory backend. Check that revised network as its root component and
use `--reuse-comparison` with the preceding result. The assembly command below
also updates an existing larger source project, preserving later consumer rules.
See the [queue refinement results](../../../docs/dxball-warning-boundary-investigation.md#queue-read-boundary-refinement)
for scope and retained evidence.

## Refine queued-event memory

The later frame/blast boundary admits the demonstrated raw coordinates through
live byte services. Six further connected cases cover saved-board aliases,
occupied pending bytes, signed neighbors, wrapped drawing positions, allocation
callbacks and expiry callbacks. They run sixteen frames each without game
startup. The other four connected cases retain their original twelve frames.

Use retained direct frame, direct brick, connected brick and normal warning
inputs. These commands revise existing packages; they do not rebuild the pilot:

```sh
python tests/fixtures/dxball-brick-actions/refine-event-memory.py prepare frame \
  /tmp/dx-play-check/inputs /tmp/dx-event-frame
python tests/fixtures/dxball-brick-actions/refine-queue.py \
  /tmp/dx-bricks-check/inputs /tmp/dx-event-brick
python tests/fixtures/dxball-brick-actions/refine-event-memory.py prepare connected \
  /tmp/dx-brick-network-check/inputs /tmp/dx-event-network
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-event-frame/package --output /tmp/dx-event-frame-check
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-event-brick/package --output /tmp/dx-event-brick-check
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-event-network/package --output /tmp/dx-event-network-check
```

`prepare normal /tmp/dx-warning-normal-check/inputs /tmp/dx-event-normal` updates
both suppliers in the retained normal network; check it as `last-brick-warning`
with `--comparison-timeout 55`. The recipe explicitly reviews the existing
`ball-motion/game-consumer` and `pickup-lifecycle/game-consumer` edges. The smaller
connected package reviews `brick-actions/frame-consumer`. Repeated adapter-only
updates do not re-review an already identical contract. Review remains an
operator assertion; it does not establish a composition proof.

Apply both changed boundaries to a copy of the source project. Assembly updates
the affected service providers while preserving their other behavior and the
later consumers' Makefile rules:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-event-frame-check --comparison /tmp/dx-event-brick-check \
  --accept-boundary-change gameplay-frame --accept-boundary-change brick-actions \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-brick-actions/refine-event-memory.py assemble {project} /tmp/dx-event-frame-check /tmp/dx-event-brick-check /tmp/dx-event-network-check' \
  --check-command 'make -j2' --check-command 'python check-play.py' \
  --check-command 'python check-bricks.py' --check-command 'python check-brick-network.py'
```

For the later 33-component project, also supply check commands for
`check-frame-motion.py`, `check-pickup-frame.py`, `check-particle-frame.py`,
`check-paddle-frame.py`, `check-shot-frame.py`, `check-explosion-frame.py`,
`check-power-frame.py`, `check-progress-frame.py` and `check-warning-history.py`.
Each accepts `--runner` for an AArch64 build. The
[results](../../../docs/dxball-event-memory-continuation.md) record native/source
comparisons, a locally diagnosed deliberate defect, exact reuse and limitations.

## Earlier consumers and integration

Connect the existing frame and motion implementations:

```sh
python tests/fixtures/dxball-brick-actions/prepare-connected.py \
  /tmp/dx-bricks/brick-actions /tmp/dx-motion-check/inputs \
  /tmp/dx-play-check/inputs /tmp/dx-brick-network
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-brick-network/package \
  --output /tmp/dx-brick-network-check
```

Four cases run twelve actual gameplay frames each. Ball collisions call the brick
component, blasts enqueue neighboring events, the frame consumes those events,
and effects animate and expire. Shared effect identities are mapped between the
frame's opaque references and the brick component's payload views. The adapters
use the existing interfaces; no checker or compiler changes are required.

Apply to a copy of the preceding portable motion source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-bricks-check --accept-boundary-change brick-actions \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-brick-actions/assemble.py {project} /tmp/dx-bricks-check /tmp/dx-brick-network-check' \
  --check-command 'make -j2' --check-command 'python check-bricks.py' \
  --check-command 'python check-brick-network.py'
```

The resulting checks use ordinary C and standard Python, with no original game,
Wine or lifting tools at runtime. Both accept `--runner /path/to/qemu-aarch64`
for a cross build. Unaffected components, objects and comparison evidence remain
reusable.

An independent native-helper consumer reduces the real-game pickup discrepancy:

```sh
python tests/fixtures/dxball-brick-actions/prepare-pickup.py \
  /tmp/dx-bricks/brick-actions /tmp/dx-pickup
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-pickup/package --output /tmp/dx-pickup-check
```

This executes the actual `0x406ef0` pickup helper and native CRT random generator
under either brick implementation, using the retained collision coordinates and
velocity. Seeds 1 and 2 exercise pickup creation and no creation, in both particle
modes. `prepare-pickup.py ... --unequal` creates a deliberate unequal-input
negative: check `--case pickup-seed-1-fast` and the workbench reports the different
random result before the changed pickup outcome. No game startup is needed.

A second reduction exercises the frame's palette clock boundary:

```sh
python tests/fixtures/dxball-brick-actions/prepare-palette.py \
  /tmp/dx-play-check/inputs /tmp/dx-palette
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-palette/package --output /tmp/dx-palette-check
```

Four cases call the actual native elapsed and palette-cycle helpers from the
original or C frame, immediately before and at the paused/running deadlines.
A local palette object observes the actual byte changes and `SetEntries` calls;
neither DirectDraw nor game startup is needed. `--unequal` and
`--case paused-before-deadline` retain a one-tick input difference that changes
the palette outcome. These helper consumers are native comparisons, separate
from the portable brick/frame/motion source consumers.

The separate normal integration check retains the existing component network:

```sh
python tests/fixtures/dxball-brick-actions/prepare-normal.py \
  /tmp/dx-bricks/brick-actions /tmp/dx-motion-normal/package /tmp/dx-bricks-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball brick-actions \
  --comparison-package /tmp/dx-bricks-normal/package \
  --output /tmp/dx-bricks-normal-check --comparison-timeout 55
```

The driver launches a ball and closes after 64 gameplay frames. The native random
initializer receives clock input 1, and its input and generator state are
compared. The preceding paddle-only schedule remains active. Palette elapsed/now
calls receive `0xf0000000 + frame * 16`; the actual elapsed and palette-cycle
helpers remain active, and supplied values are observed. Other helper clocks,
delay loops and the native random generator retain their real behavior. These
are explicit environment inputs, with application state, palette and pixel checks
preserved.
The untouched control checks startup, output and exit rather than uncontrolled
random pixel equality. See the [continuation](../../../docs/dxball-brick-actions-continuation.md)
for exact results and remaining work.
