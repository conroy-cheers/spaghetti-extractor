# DX-Ball score screen

[Ordinary C](screen.c) replaces six actual score-screen entries: initialization,
redraw, update, key dispatch, table rendering and name editing. The existing menu
component still owns the shared leave routine. [The boundary](BOUNDARY.md) uses
the existing scene/font/surface objects and byte-faithful score table. Name-buffer
padding, integer flags, keyboard codes, timers and synchronous redraw callbacks
remain explicit. Code and display spans come from the executable, without original
source or third-party implementations.

In the retained lifting environment, prepare from the previous local menu and
table comparison packages:

```sh
python tests/fixtures/dxball-score-scene/prepare.py \
  /path/to/DXBall.exe /tmp/dx-menu/menu-scene /tmp/dx-scores/score-table /tmp/dx-screen
spaghetti-headless-wayland spaghetti-extractor component check dxball score-scene \
  --comparison-package /tmp/dx-screen/score-scene --output /tmp/dx-screen-check
```

Twenty cases compare all six native entries with the C and reuse the actual C
font, drawing, table and scene helpers. They cover accepted/rejected and equal
scores, unsigned extremes, empty/full names, ignored/high-bit keys, Shift values,
clock wrap, inactive timers, noncanonical flags, mouse clamping, highlight edges,
file failures and the retained score file. Text spans/positions, service order,
record/name/disk bytes, handle state, scene state and pixel backing are observed.
Selected original bodies remain trapped. Graphics/file backends here are controlled;
this is distinct from a full game-over playthrough with real assets and devices.

Apply to the existing score-table source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-screen-check --accept-boundary-change score-scene \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-score-scene/assemble.py {project} /tmp/dx-screen-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py' \
  --check-command 'python check-title.py' \
  --check-command 'python check-scene.py' \
  --check-command 'python check-menu.py' \
  --check-command 'python check-scores.py' \
  --check-command 'python check-screen.py'
```

Use an absolute lifting-Python path for assembly when the shell's default Python
lacks its dependencies. The resulting project builds without the lifting toolkit
or original executable. `CC`/`AR` select another architecture and each check script
accepts `--runner` for QEMU. It contains connected subsystem consumers; remaining
native gameplay/platform code has not yet become a standalone portable game.

Install the new entries alongside the existing normal-game network:

```sh
python tests/fixtures/dxball-score-scene/prepare-normal.py \
  /tmp/dx-screen/score-scene /tmp/dx-scores-normal/package \
  /tmp/dx-menu-normal/package /tmp/dx-screen-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball score-scene \
  --comparison-package /tmp/dx-screen-normal/package --output /tmp/dx-screen-normal-check \
  --comparison-timeout 55
```

Both named consumer requirements are explicitly refined to the reviewed live
packages. Retaining the old controlled selection while adding the live selection
is rejected as a conflict. Local and normal workloads establish separate comparison
baselines; do not pass the local check as `--reuse-comparison` for this different
case set. Within a workload, local edits can reuse its prior comparison normally.

The existing counted-input workload covers startup, title, menu and initial
gameplay before close. It does not reach the score screen, and its zero screen
call counts make that gap visible. The installed observer retains name/table
backing, state and pixels when score-screen callers are added later. See the
[continuation record](../../../docs/dxball-score-scene-continuation.md).
