# DX-Ball board rendering

[The C implementation](render.c) lifts the full-grid loop and single-cell
renderer through existing board, scene/font and graphics interfaces.
[BOUNDARY.md](BOUNDARY.md) records the shared state, aliasing and callback rules.
Authoring used executable instructions/data and assets, without original sources.

In the retained lifting environment:

```sh
python tests/fixtures/dxball-board-rendering/prepare.py \
  /path/to/DXBall.exe /tmp/dx-menu/menu-scene /tmp/dx-boards/board-data /tmp/dx-render
spaghetti-headless-wayland spaghetti-extractor component check dxball board-rendering \
  --comparison-package /tmp/dx-render/board-rendering --output /tmp/dx-render-check
```

Eight scenarios match the original entries without the game UI. Each exercises
all 256 tile bytes. Cases cover editor/gameplay scenes, damage modes, surface
aliasing, callbacks changing shared state and the local damage rectangle, and
retained board data. Full board bytes, pixels, object state and ordered graphics
and damage calls are compared. Both source entry hooks must remain intact.

Apply to a copy of the existing editor source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-render-check --accept-boundary-change board-rendering \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-board-rendering/assemble.py {project} /tmp/dx-render-check' \
  --check-command 'make -j2' --check-command 'python check-render.py'
```

The retained integration also runs all preceding consumer checks: 209 cases match
on x86-64 and AArch64. The project contains eighteen components and 65 native
entries. All seventeen neighboring
implementation/interface/contract identities remain unchanged. A configurable
graphics-recorder capacity supports full-board traces; five old test-consumer
objects recompile while 41 old objects remain byte-identical.

Select the renderer in the real editor workload:

```sh
python tests/fixtures/dxball-board-rendering/prepare-normal.py \
  /tmp/dx-render/board-rendering /tmp/dx-editor-normal/package /tmp/dx-render-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball board-rendering \
  --comparison-package /tmp/dx-render-normal/package \
  --output /tmp/dx-render-normal-check --comparison-timeout 55
```

This explicitly rebinds the local consumer to live shared objects and platform
services. Clear/save/close matches, including rendering state and saved bytes.
Local cases cover gameplay values and callbacks beyond this workload. Remaining
region/cursor/damage helpers, gameplay, startup and portable backends still need
lifting. See the [continuation record](../../../docs/dxball-board-rendering-continuation.md)
for the initial fixture correction and retained evidence.
