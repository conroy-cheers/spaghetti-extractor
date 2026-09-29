# DX-Ball warning and historical inputs

This directory retains the native investigation and the subsequent portable
implementation. See [lifted warning and caller history](#lifted-warning-and-caller-history)
for the authoring, comparison and assembly workflow.

The original diagnostic executes the native brick count (`0x408900`), brick hit (`0x405c80`) and last-brick
warning (`0x408c20`) from PE32 SHA256
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.
No original game source is used. No game startup or UI automation is needed.

Run in the repository development environment, always under headless Wayland:

```sh
spaghetti-headless-wayland python tests/fixtures/dxball-warning/probe-residue.py \
  /path/to/DXBall.exe /tmp/dx-warning-residue
python tests/fixtures/dxball-warning/probe-residue.py \
  --review /tmp/dx-warning-residue/result.json
```

The output directory must not already exist. The first command uses the existing
native entry adapters, experimental import, capture launcher and bounded Wine
session. Application output and Wine diagnostics remain separate. The second
checks the retained observations without compilation or Wine startup; it fails
if the expected control and counterexamples are absent. `result.json` retains
execution evidence and timings; `review.json` records the boundary finding.

`entry-residue.c` puts one tile at column 1, row 1 and calls the actual count.
For bytes 23 and 255 it then calls the actual hit operation. It checks the
current count separately from the game's retained remaining-brick count.
The timer is expired (deadline 1, clock 2), the fast flag is 1, random returns 0,
and sprite slot 1 of bank 2 is 159 by 479. Audio, drawing, queuing and effects
are controlled services. Queue and explosion arguments, particle count, warning
rectangle and frame count are observed. These services are not full game consumers.

A naked native entry shim seeds three otherwise unwritten local words at entry
ESP offsets -28, -24 and -20, then jumps directly to the unchanged warning body.
This preserves its entry ESP and return address. The two seeds are
`[y=120, row=2, column=3]` and `[y=300, row=5, column=7]`.

| Initial tile | Native state before warning | First seed | Second seed |
| --- | --- | --- | --- |
| 5 | One eligible cell; remaining 1 | Queue (1,1), explosion (65,72) | Same |
| 0 | Empty; remaining 0; direct-call diagnostic | Queue (3,2), explosion (3,120) | Queue (7,5), explosion (7,300) |
| 23 or 255, then hit | Empty; remaining 1 | Queue (3,2), explosion (3,120) | Queue (7,5), explosion (7,300) |

The warning scans for cells other than 0 and 2. If it finds none, column, row
and y remain old stack contents; initial x is the old column word. The final
two rows are not interchangeable: only the count/hit sequence demonstrates an
empty board with the remaining count that enables the actual frame's warning
call. It does not establish a complete route through file loading, collisions
and the running game. Board loading accepts raw tile bytes, so a tile-range
invariant cannot simply be assumed.

Existing scalar/shared-object interfaces can expose these three inputs, and
defined C can consume them. At this diagnostic stage the portable frame/service boundary did
not supply the corresponding legacy stack history. A native shim alone cannot
establish that history after callers have been independently recompiled. Before
claiming this case composes, trace its producers and transport the relevant state
through an explicit compatibility adapter or a sufficiently connected boundary.
Do not initialize the missing values arbitrarily, introduce uninitialized C
locals, or silently exclude accepted board bytes.

The local reproduction needs no new tool internals. Portable state transport
was unresolved at this stage; no conclusion that the interface language is incapable of
expressing it has been established. The native-only diagnostic left the prior source project unchanged.

## Trace the producers and the queue's actual read

```sh
spaghetti-headless-wayland python tests/fixtures/dxball-warning/probe-frame.py \
  /path/to/DXBall.exe /tmp/dx-warning-frame
spaghetti-headless-wayland python tests/fixtures/dxball-warning/probe-frame.py \
  --queue-alias /path/to/DXBall.exe /tmp/dx-warning-queue
python tests/fixtures/dxball-warning/probe-frame.py \
  --review /tmp/dx-warning-frame/result.json
python tests/fixtures/dxball-warning/probe-frame.py \
  --review /tmp/dx-warning-queue/result.json
```

`frame-provenance.c` runs the actual frame, paddle draw, sprite draw, pickup draw,
particle draw and warning. It observes the three words at the existing warning
call site without writing them. Other frame services and graphics/audio effects
are controlled. Incoming frame EBP/ESI are explicit inputs: six cases use 2/120;
two use the loaded DispatchMessageA/PeekMessageA addresses. The latter matches
the register setup in the reviewed normal direct call chain, not a full startup
experiment. Warning queue/explosion/creation calls remain controlled observations.

| Last applicable producer | Warning words `[y,row,column]` |
| --- | --- |
| Paddle, with the fixture's width/phase/gun state | `[1,84,0]` |
| Ball sprite | `[0,incoming_ESI,incoming_EBP]` |
| Pickup sprite | `[incoming_ESI,incoming_EBP,1]` |
| Particle description/lock | Surface descriptor words 20, 21, 22 |

An empty pickup or particle list leaves the preceding words intact. The partial
descriptor case writes words 20/21 during describe and only word 21 during lock,
retaining column zero from paddle drawing; it ends with `[120,5,0]`. The
ball-then-pickup case checks that the later producer wins. Eight native cases
verify these relationships and the actual warning service arguments. Four
produce queue coordinates outside the currently admitted 20-by-20 grid.

`queue-alias.c` then runs the actual queue body at `(0,84)`. Native arithmetic
reads address `0x42ca60 + 20*84 = 0x42d0f0`, which is saved-board storage at offset
760 from `0x42cdf8`: saved board 1, row 18, column 0. Both cases keep the active
board empty. Saved byte zero allocates nothing; saved byte seven allocates an
event with kind 1, column 0 and row 84 and sets the voice flag. Allocation is a
controlled service providing a real five-word node. The then-existing portable queue was not executed outside its admitted domain,
where its C array indexing would be undefined. The subsequent queue refinement
replaced that read with an explicit service.

These results establish a concrete refinement path using existing context,
service and byte-view facilities. A compatibility adapter must retain the
reviewed machine-visible words and their producers; an address view must resolve
queue reads to the same live current/saved-board storage or other admitted native
memory. Wider contracts also need explicit outcomes for unmapped accesses.
Returning zero for every out-of-grid access would contradict this experiment.
These diagnostic probes alone did not implement the views/adapter or establish checked summaries. No portable
selection or previous comparison receipt is promoted by these native diagnostics.

## Lifted warning and caller history

`warning.c` implements preparation/drawing using shared objects and an explicit
fallback input. `history.h` supplies the reviewed producer projections. The
connected source consumer runs the actual lifted frame, paddle, pickup, particle
and warning code against the retained original frame observations.

```sh
python tests/fixtures/dxball-warning/prepare.py /path/to/DXBall.exe \
  /tmp/dx-game-check/inputs /tmp/dx-warning
spaghetti-headless-wayland spaghetti-extractor component check dxball last-brick-warning \
  --comparison-package /tmp/dx-warning/last-brick-warning --output /tmp/dx-warning-check
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-warning-check --accept-boundary-change last-brick-warning \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-warning/assemble.py {project} /tmp/dx-warning-check /tmp/dx-warning-frame/result.json' \
  --check-command 'make -j2' --check-command 'python check-warning.py' \
  --check-command 'python check-warning-history.py'
```

Use a copy of the preceding source project. Both source checks accept
`--runner /path/to/qemu-aarch64`. The history check uses numeric original-environment
register inputs from the retained traces; it needs no original image or Wine.
Unexpected service calls fail explicitly. Audio/rendering and queue requests
remain controlled; downstream out-of-grid event consumption has not been lifted
by this consumer.

For scoped normal execution with the existing game network:

```sh
python tests/fixtures/dxball-warning/prepare-normal.py /tmp/dx-warning-check/inputs \
  /tmp/dx-game-normal/inputs /tmp/dx-warning-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball last-brick-warning \
  --comparison-package /tmp/dx-warning-normal/package --output /tmp/dx-warning-normal-check \
  --comparison-timeout 55
```

This backend uses synchronized native storage and the reviewed WinMain call
context. It preserves descriptor history through native services and captures
original warning entry words before its wrapper. Inspect `selected_warning` for
actual execution: the retained normal workload only reaches inactive drawing.
See the [continuation](../../../docs/dxball-warning-continuation.md) for exact
results, reuse and the remaining event-consumer/platform obligations.
