# DX-Ball line and region fill

`raster.c` replaces both complete machine bodies with ordinary C, using existing
surface, rectangle and pixel-view types. Native code and C use the same shared
DirectDraw backend. This fixture contains no COM vtables or fill emulation.
[BOUNDARY.md](BOUNDARY.md) records the exact arithmetic and memory scope.

Inside the existing development environment:

```sh
python tests/fixtures/dxball-raster/prepare.py /path/to/DXBall.exe \
  /path/to/math-normal-check/inputs /tmp/raster
spaghetti-headless-wayland spaghetti-extractor component check dxball raster-drawing \
  --comparison-package /tmp/raster/raster-drawing --output /tmp/raster-check
```

The 18 cases cover both axis branches and all octants, points and diagonals,
negative pitch, writable padding, wrapped deltas, full color arguments, post-lock
geometry, failures/retries, two shared surfaces and a callback. The first C passes
unchanged. No original application source is used.

A useful edit changes the horizontal-major comparison from `>` to `>=`, drawing
the final pixel in the wrong row. Replay it locally:

```sh
spaghetti-extractor component start dxball raster-drawing \
  --comparison-package /tmp/raster-check/inputs \
  --source-file source/raster.c=/path/to/edit.c --output /tmp/raster-edit
spaghetti-headless-wayland spaghetti-extractor component check dxball raster-drawing \
  --comparison-package /tmp/raster-edit --case strict-thresholds \
  --reuse-comparison /tmp/raster-check --output /tmp/raster-replay
```

Apply to a copy of the preceding numeric source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/raster-check --accept-boundary-change raster-drawing \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-raster/assemble.py {project} /tmp/raster-check' \
  --check-command 'make -C {project} raster audio audio-setup wave file-reader mds-parser mds-loader mds-stream' \
  --check-command 'python {project}/check-raster.py' \
  --check-command 'python {project}/check-audio.py' \
  --check-command 'python {project}/check-audio-setup.py' \
  --check-command 'python {project}/check-wave.py' \
  --check-command 'python {project}/check-reader.py' \
  --check-command 'python {project}/check-mds-parser.py' \
  --check-command 'python {project}/check-mds-loader.py' \
  --check-command 'python {project}/check-mds-stream.py'
```

The shared backend refresh also rechecks seven existing consumers (279 cases),
retaining their component implementations. For AArch64 pass its `CC`/`AR` to make
and `--runner /path/to/qemu-aarch64` to each check. These exported consumers build
and run without the workbench.

For the actual game workload:

```sh
python tests/fixtures/dxball-raster/prepare-normal.py /tmp/raster-check/inputs \
  /path/to/math-normal-check/inputs /tmp/raster-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/raster-normal/package \
  --reuse-comparison /path/to/math-normal-check --output /tmp/raster-normal-check
```

The normal adapter binds borrowed surfaces by the named primary, back, flip and
software roots. View-cache encounter order is not a correspondence identity.
Ownership stays with the program; the backend observes real Wine calls. Full
pixel snapshots use lossless references and patches. No original/replacement
role reaches the backend.

Evidence: `build/shared-wine-draw-2026-09-29/`. `raster-delivery` passes 18 cases;
`defect-check` catches the threshold edit. `normal-delivery` selects 242 line calls
and one fill, preserving 64 frames and all 46 preceding non-platform fields.
The selection has 49 components, 190 entries and 1,180 retained cases. Both source
architectures pass the new and affected consumers. Full
[program assembly](../dxball-standalone/README.md) remains outstanding.
