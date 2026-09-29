# DX-Ball title scene

[Ordinary C](scene.c) replaces the existing enter, redraw, update, key and leave
functions for scene 4. [Shared state](scene-state.h) extends the existing font,
animation, palette and flow objects. The [boundary](BOUNDARY.md) records native
ranges, service interactions and the finite comparison scope. Display text is
extracted as exact byte spans from the pinned executable; original source is not
used.

From the lifting environment, reuse the
[animation comparison package](../dxball-title-animation/README.md):

```sh
python tests/fixtures/dxball-title-scene/prepare.py \
  /path/to/DXBall.exe /tmp/dx-title/title-animation /tmp/dx-scene
spaghetti-headless-wayland spaghetti-extractor component check dxball title-scene \
  --comparison-package /tmp/dx-scene/title-scene --output /tmp/dx-scene-check
```

Twelve cases run all five actual native bodies. They cover nested redraw,
presentation branches, capability messages, callback mutation, signed mouse
coordinates, button values, palette limits and both leave reasons. Source-side
machine bodies are trapped. File/audio/damage/presentation services are controlled
for these local cases; animation, fonts, destination selection and cleanup use the
existing components. Palette bytes, pixel backing, state and interactions are
retained.

Apply to the existing animation source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-scene-check --accept-boundary-change title-scene \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-title-scene/assemble.py {project} /tmp/dx-scene-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py' \
  --check-command 'python check-title.py' \
  --check-command 'python check-scene.py'
```

Use an absolute lifting-Python path in the assembly command if another `python`
appears first in the retained shell. The resulting project builds ordinary C
without the lifting toolkit or original executable. `CC`/`AR` select the compiler;
check scripts accept `--runner /path/to/qemu-aarch64` for cross-architecture runs.

For normal game execution, use the existing title-animation live package:

```sh
python tests/fixtures/dxball-title-scene/prepare-normal.py \
  /tmp/dx-scene/title-scene /tmp/dx-title-normal/package /tmp/dx-scene-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball title-scene \
  --comparison-package /tmp/dx-scene-normal/package --output /tmp/dx-scene-normal-check \
  --comparison-timeout 55
```

This recipe explicitly refines the `animation-consumer` requirement to the live
consumer's contract and uses its actual PCX/loader/graphics services. The controlled
and live consumers have different assumptions even though they share component C;
the public refinement API handles that switch. The existing counted-input
controller is reused unchanged. All twelve components execute in the real game;
the standalone project remains a set of subsystem consumers until other scene
bodies and platform backends are lifted. See the
[continuation record](../../../docs/dxball-title-scene-continuation.md).
