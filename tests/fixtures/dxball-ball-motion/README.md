# DX-Ball ball motion

[motion.c](motion.c) lifts five real native entries: ball creation, movement,
paddle rebound, brick contact and removal. The component shares the frame's ball
records, sprite objects and current board. Allocation, audio, particles, brick
actions and life loss remain explicit services. [BOUNDARY.md](BOUNDARY.md)
records their state, lifetime and numeric assumptions. No original game source
was consulted.

Prepare with the pinned executable and the preceding frame/board packages:

```sh
python tests/fixtures/dxball-ball-motion/prepare.py \
  /path/to/DXBall.exe /tmp/dx-play-check/inputs /tmp/dx-board-check/inputs \
  /tmp/dx-motion
spaghetti-headless-wayland spaghetti-extractor component check dxball ball-motion \
  --comparison-package /tmp/dx-motion/ball-motion --output /tmp/dx-motion-check
```

The 29 local cases call the actual original operations without game startup or
neighboring bodies. They cover attached and launched motion, walls, paddle zones,
sticky/piercing balls, particles, brick directions, allocation/removal, service
mutation and generated sequences. Observations include complete live payloads,
links and cursors, the board, sprite bytes and ordered service calls before and
after mutation. The original removal iterator can skip a ball; the C preserves
that behavior. Allocation failure retains the original exit path but is outside
the successful-allocation comparison cases.

The ball type now uses the public interface's opaque struct tag, with unchanged
layout and behavior. Refine the preceding frame package and recheck its sixteen
cases before connecting it:

```sh
spaghetti-extractor component start dxball gameplay-frame \
  --comparison-result /tmp/dx-play-check \
  --source-file source/play-state.h=/path/to/repo/tests/fixtures/dxball-gameplay/play-state.h \
  --output /tmp/dx-motion-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-motion-frame --reuse-comparison /tmp/dx-play-check \
  --output /tmp/dx-motion-frame-check
python tests/fixtures/dxball-ball-motion/prepare-frame.py \
  /tmp/dx-motion/ball-motion /tmp/dx-motion-frame /tmp/dx-frame-motion
spaghetti-headless-wayland spaghetti-extractor component check dxball ball-motion \
  --comparison-package /tmp/dx-frame-motion/package \
  --output /tmp/dx-frame-motion-check
```

This small connected consumer runs two actual gameplay frames per case over the
same ball and board objects. Six scenarios cover attachment, launch, flight,
removal, brick contact and callback changes. Other frame helpers are controlled
and observed. It needs no game startup or graphics backend.

Apply both matching components to a copy of the preceding portable source
project. The explicit boundary acknowledgements follow review of the new ball
service bindings and the frame's shared type tag:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-motion-frame-check --comparison /tmp/dx-motion-check \
  --accept-boundary-change gameplay-frame --accept-boundary-change ball-motion \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-ball-motion/assemble.py {project} /tmp/dx-motion-check /tmp/dx-frame-motion-check' \
  --check-command 'make -j2' --check-command 'python check-motion.py' \
  --check-command 'python check-frame-motion.py' --check-command 'python check-play.py'
```

The resulting `motion` and `frame-motion` programs execute without the original
game, Wine or lifting tools. Their checks compare retained original observations
using standard Python. Each check also accepts `--runner /path/to/qemu-aarch64`
for a cross build. Ordinary edits can therefore be diagnosed locally on either
architecture; game execution is an additional integration check.

For that separate check, use the preceding gameplay normal package:

```sh
python tests/fixtures/dxball-ball-motion/prepare-normal.py \
  /tmp/dx-motion/ball-motion /tmp/dx-play-normal/package /tmp/dx-motion-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball ball-motion \
  --comparison-package /tmp/dx-motion-normal/package \
  --output /tmp/dx-motion-normal-check --comparison-timeout 55
```

The counted input driver launches a ball and closes after sixteen gameplay
frames. Native allocation/audio/effects remain real services, and the existing
C component network remains selected. Full ball/board state, frame pixels and
the existing paddle clock/random input schedule are observed. This workload is
not a full playthrough and does not reach every collision or helper.

Any integration discrepancy must become a local or small connected regression,
including its environment inputs. An interaction that cannot be expressed or
executed there is a tooling gap. Finite tests cannot ensure every input has
already been covered. Exact evidence, reuse and remaining work are recorded in
the [continuation](../../../docs/dxball-ball-motion-continuation.md).
