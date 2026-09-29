# DX-Ball explosion lifecycle

[explosion.c](explosion.c) lifts reset, creation and drawing/expiry from the pinned
executable into 48 lines of C. Authoring uses instructions/data, without original
game source. [BOUNDARY.md](BOUNDARY.md) records the shared roots, record layout,
callback effects, native wrapping arithmetic and lifetime assumptions.

The component borrows the existing gameplay current/first slots and owns the tail
and retained word. The frame sees opaque effect identities; the owner reads the
same concrete C records. Allocation, disposal, termination and sprite drawing
are the four services. No neighboring interface or implementation changes.

Prepare and compare native entry bodies without game startup:

```sh
python tests/fixtures/dxball-explosions/prepare.py \
  /path/to/DXBall.exe /tmp/dx-shots-check/inputs /tmp/dx-explosions
spaghetti-headless-wayland spaghetti-extractor component check dxball explosion-lifecycle \
  --comparison-package /tmp/dx-explosions/explosion-lifecycle --output /tmp/dx-explosions-check
```

Twenty-one scenarios cover reset with live orphaned records, append, signed and
wrapping coordinate clamps, allocation/termination callbacks, drawing, expiry at
each list position, skipped successors, graphics/free callbacks, signed frame
wrap, full lifecycles and caller changes to current. All live payloads, links,
roots and ordered service arguments/results are observed. Allocation failure
uses a returning controlled termination backend with a live current record;
this checks the call and continuation, not actual process termination.

Connect the existing ball-motion and gameplay-frame components:

```sh
python tests/fixtures/dxball-explosions/prepare-frame.py \
  /tmp/dx-explosions/explosion-lifecycle /tmp/dx-motion-check/inputs \
  /tmp/dx-frame-check/inputs /tmp/dx-explosion-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball explosion-lifecycle \
  --comparison-package /tmp/dx-explosion-frame/package --output /tmp/dx-explosion-frame-check
```

Four 26-frame cases use actual frame, ball-motion and explosion bodies. Contact
creates an explosion, animation runs for 22 steps, and the cleared level advances
only after disposal. Piercing suppresses creation; preexisting expired records
exercise the extra iterator advance; pausing preserves records. Graphics, brick
hits and remaining helpers are controlled and observed. These consumers exercise
shared-root changes and lifetime without a game UI or full graphics backend.

Apply to a copy of the preceding shot source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-explosions-check --accept-boundary-change explosion-lifecycle \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-explosions/assemble.py {project} /tmp/dx-explosions-check /tmp/dx-explosion-frame-check' \
  --check-command 'make -j2' --check-command 'python check-explosions.py' \
  --check-command 'python check-explosion-frame.py'
```

These source consumers use C and Python without Wine or the game. Their check
scripts accept `--runner /path/to/qemu-aarch64` for cross builds. Unchanged component
records, objects and consumer evidence are reused.

Select the C in the existing normal-game comparison:

```sh
python tests/fixtures/dxball-explosions/prepare-normal.py \
  /tmp/dx-explosions/explosion-lifecycle /tmp/dx-shots-normal-check/inputs /tmp/dx-explosions-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball explosion-lifecycle \
  --comparison-package /tmp/dx-explosions-normal/package \
  --output /tmp/dx-explosions-normal-check --comparison-timeout 90
```

This retains the 64-frame launch/close workload, inputs and preceding twenty-seven
components. The native adapter maps concrete records to the parent's opaque effect
views at each boundary, preserving root aliases, reachable contents and lifetime.
Native allocation/termination remain active and drawing reaches lifted components.
Inspect `selected_explosions` for entry coverage; empty-list drawing alone does not
establish creation or allocator coverage. Every semantic integration discrepancy
must become a local or small connected regression; inability to express it is a
tooling gap.
