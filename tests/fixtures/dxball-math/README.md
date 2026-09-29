# DX-Ball numeric support

`math.c` replaces eight complete bodies: table initialization, integer/floating
sine and cosine readers, coordinate projections and sound pan. The boundary uses
ordinary C and libm, preserving the original approximate radians constant,
wrapping arithmetic and neighboring storage read by extreme angles.
[BOUNDARY.md](BOUNDARY.md) records the admitted storage and floating environment.
No original application source is used.

Inside the existing development environment, prepare and compare:

```sh
python tests/fixtures/dxball-math/prepare.py /path/to/DXBall.exe \
  /path/to/runtime-normal-check/inputs /tmp/math
spaghetti-headless-wayland spaghetti-extractor component check dxball math-support \
  --comparison-package /tmp/math/math-support --output /tmp/math-check
```

Nine cases cover every initialized table entry, repeated initialization, angle
extremes and sweeps, wrapping projections over initialized/arbitrary tables, and
pan extremes, sweeps and generated inputs. Whole-storage observations include the
unmodified gap and following words. As a useful defect replay, replacing the
native radians constant with true pi/180 changes sine entry 90 from 1023 to 1024:

```sh
spaghetti-extractor component start dxball math-support \
  --comparison-package /tmp/math-check/inputs \
  --source-file source/math.c=/path/to/edit.c --output /tmp/math-edit
spaghetti-headless-wayland spaghetti-extractor component check dxball math-support \
  --comparison-package /tmp/math-edit --case initialize \
  --reuse-comparison /tmp/math-check --output /tmp/math-replay
```

Apply the matching selection to a copy of the preceding runtime source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/math-check --accept-boundary-change math-support \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-math/assemble.py {project} /tmp/math-check' \
  --check-command 'make -C {project} math' \
  --check-command 'python {project}/check-math.py'
```

For AArch64 supply its `CC` and `AR` in the make command and add
`--runner /path/to/qemu-aarch64` to the check. The numeric consumer links `-lm`.
Previous component implementations, records, objects and consumers are reused.

For actual game execution:

```sh
python tests/fixtures/dxball-math/prepare-normal.py /tmp/math-check/inputs \
  /path/to/runtime-normal-check/inputs /tmp/math-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball music-control \
  --comparison-package /tmp/math-normal/package \
  --reuse-comparison /path/to/runtime-normal-check --output /tmp/math-normal-check
```

The normal adapter publishes only the two 361-entry table ranges. Existing
callers inline six reader/projection helpers; their separate bodies are exercised
locally. The retained normal workload executes initialization once and pan twice,
preserving all 46 previous observation fields, 64 frames and 766 platform calls.
It compiles three translation units and reuses 101 objects.

Evidence is under `build/dxball-math-raster-2026-09-29/`: `math-check`,
`defect-check`, `normal-check`, both public apply receipts, `source-audit` and
`validation.json`. Both x86-64 and emulated AArch64 consumers pass. The selection
has 48 components, 188 entries and 1,162 retained cases; it remains a set of
source subsystem consumers, not a standalone game. The next raster boundary
needs shared DirectDraw testing support, followed by the remaining
[program assembly work](../dxball-standalone/README.md).
