# DX-Ball shot lifecycle

[shot.c](shot.c) lifts movement, firing and removal from the pinned executable
into 65 lines of C. Authoring uses executable instructions/data, without original
game source. [BOUNDARY.md](BOUNDARY.md) records the shared objects, allocation
contents, callback effects, arithmetic and lifetime assumptions.

The existing gameplay shot records and motion state are reused unchanged.
Allocation exposes opaque backing storage; ordinary C converts its address to
the existing record type. There is no duplicate shot layout or new neighboring
interface. Disposal, termination, randomness, brick hits and sound are services.

Prepare and compare native entry bodies without game startup:

```sh
python tests/fixtures/dxball-shots/prepare.py \
  /path/to/DXBall.exe /tmp/dx-paddles-check/inputs /tmp/dx-shots
spaghetti-headless-wayland spaghetti-extractor component check dxball shot-lifecycle \
  --comparison-package /tmp/dx-shots/shot-lifecycle --output /tmp/dx-shots-check
```

Thirty scenarios cover pair creation, nonzero allocation payloads, signed crop
rounding, allocation/sound callbacks, every removal position, null removal,
free callbacks, flight, ceiling expiry, board hits, piercing, skipped successors,
random/hit callbacks, all random choices, sprite-bank aliases and valid linear
board aliases. A 64-step case fires, moves and expires a pair. Allocation failure
uses a returning controlled termination service with a valid current object;
this checks the call and continuation, not actual process termination.

Observations include live payloads/links, roots, counters, shared board bytes,
sprite metadata and ordered service arguments/results. Every native or C service
boundary transports the same live objects, including callback changes.

Connect the existing gameplay-frame component:

```sh
python tests/fixtures/dxball-shots/prepare-frame.py \
  /tmp/dx-shots/shot-lifecycle /tmp/dx-frame-check/inputs /tmp/dx-shot-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball shot-lifecycle \
  --comparison-package /tmp/dx-shot-frame/package --output /tmp/dx-shot-frame-check
```

Four eight-frame cases exercise firing, movement, drawing, hits, piercing, pausing
and expiry. The native firing condition is count below six; appending a pair can
therefore produce seven shots when the prior count is five. That behavior is
retained. Both actual component bodies execute, while remaining frame/brick/sound
services are controlled and observed. No game UI or graphics backend is needed.

Apply to a copy of the preceding paddle source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-shots-check --accept-boundary-change shot-lifecycle \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-shots/assemble.py {project} /tmp/dx-shots-check /tmp/dx-shot-frame-check' \
  --check-command 'make -j2' --check-command 'python check-shots.py' \
  --check-command 'python check-shot-frame.py'
```

These source consumers need C and Python, without Wine or the original game.
Their check scripts accept `--runner /path/to/qemu-aarch64` for cross builds.
Unchanged component records, objects and consumer evidence are reused.

Select the shot C in the existing normal-game comparison:

```sh
python tests/fixtures/dxball-shots/prepare-normal.py \
  /tmp/dx-shots/shot-lifecycle /tmp/dx-paddles-normal-check/inputs /tmp/dx-shots-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball shot-lifecycle \
  --comparison-package /tmp/dx-shots-normal/package \
  --output /tmp/dx-shots-normal-check --comparison-timeout 90
```

This retains the 64-frame launch/close workload and its input schedule, selects
the preceding twenty-six components and retains their observations. Native
allocation, termination and sound remain active; hits reach the lifted brick
component. Inspect `selected_shots` for actual entry coverage: an empty-list
movement call does not establish firing or real allocator coverage. Local and
connected cases exercise those paths independently. Every semantic integration
discrepancy must become a retained local or small connected regression; inability
to express it is a tooling gap.
