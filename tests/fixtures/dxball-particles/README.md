# DX-Ball particle lifecycle

[particle.c](particle.c) implements the actual creation, movement/expiry and
pixel-drawing entries in 88 lines of ordinary C. Authoring uses the pinned
executable's instructions and data, without original game source.
[BOUNDARY.md](BOUNDARY.md) records list/lifetime rules, callbacks and the shared
software surface. The software-surface slot is borrowed separately from the
font destination; the existing PCX image-view type is reused.

Prepare and compare the native entry bodies without game startup:

```sh
python tests/fixtures/dxball-particles/prepare.py \
  /path/to/DXBall.exe /tmp/dx-pickups-check/inputs /tmp/dx-particles
spaghetti-headless-wayland spaghetti-extractor component check dxball particle-lifecycle \
  --comparison-package /tmp/dx-particles/particle-lifecycle --output /tmp/dx-particles-check
```

Twenty scenarios cover creation bounds, append callbacks, allocation failure's
termination call, signed counters, gravity, expiry, list skipping, free callbacks,
pixel colors, lock retries, callback changes to objects/destinations and a
forty-step lifecycle. The allocation-failure scenario uses an explicitly
returning controlled termination service; it does not claim actual process-exit
coverage. The normal backend invokes the original termination routine.

Observations include roots, all live payloads/links, allocation/free identity,
service arguments/results and exact pixel changes, including padding and guard
bytes. Pixel changes use a sparse encoding against known initial bytes; every
byte is inspected. No screenshot or complete graphics backend is required.

Connect an existing gameplay-frame workspace:

```sh
python tests/fixtures/dxball-particles/prepare-frame.py \
  /tmp/dx-particles/particle-lifecycle /tmp/dx-frame-check/inputs /tmp/dx-particle-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball particle-lifecycle \
  --comparison-package /tmp/dx-particle-frame/package --output /tmp/dx-particle-frame-check
```

Four eight-frame scenarios exercise expiry, edge removal, pausing and creation
from a controlled helper during a frame. Both frame and particle bodies execute;
remaining frame helpers are controlled. Font and particle destinations differ.
This check preserves shared objects between operations without game startup.

Apply to a copy of the preceding pickup source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-particles-check --accept-boundary-change particle-lifecycle \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-particles/assemble.py {project} /tmp/dx-particles-check /tmp/dx-particle-frame-check' \
  --check-command 'make -j2' --check-command 'python check-particles.py' \
  --check-command 'python check-particle-frame.py'
```

These consumers need ordinary C and Python, with no Wine or game runtime.
Their check scripts accept `--runner /path/to/qemu-aarch64` for cross builds.
Existing component records, objects and unaffected consumer evidence are reused.

Select the particle C in the existing normal-game comparison:

```sh
python tests/fixtures/dxball-particles/prepare-normal.py \
  /tmp/dx-particles/particle-lifecycle /tmp/dx-pickups-normal-check/inputs /tmp/dx-particles-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball particle-lifecycle \
  --comparison-package /tmp/dx-particles-normal/package \
  --output /tmp/dx-particles-normal-check --comparison-timeout 55
```

This retains the existing launch/close workload and its explicit seed, paddle
and palette-clock inputs. Allocation, DirectDraw and remaining native helpers
stay active; particles call the already lifted damage component. Local checks
independently exercise expiry and service/callback variants that this workload
may not reach. Any integration discrepancy must become a local or small connected
regression; inability to express it through existing facilities is a tooling gap.
