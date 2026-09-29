# DX-Ball sprite drawing continuation

This binary-only component adds destination selection and transparent/opaque
sprite drawing to the existing font, cleanup and asset-loading source project.
Read [BOUNDARY.md](BOUNDARY.md) for state, alias and service obligations. Only the
pinned executable, its disassembly and existing operator-authored C were used.

Use the toolkit Python and C tools from `nix develop .#lifting`. The previous
[font/asset recipe](../dxball-sprite-font/README.md) supplies the neighboring
comparison package and standalone project; neither needs a pilot rebuild.

```sh
python tests/fixtures/dxball-sprite-drawing/prepare.py \
  /path/to/DXBall.exe /tmp/dx-font/font-render /tmp/dx-drawing
spaghetti-headless-wayland spaghetti-extractor component check dxball sprite-drawing \
  --comparison-package /tmp/dx-drawing/sprite-drawing --output /tmp/dx-drawing-check
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-drawing-check --accept-boundary-change sprite-drawing \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-sprite-drawing/assemble.py {project} /tmp/dx-drawing-check' \
  --check-command 'make -C {project}' \
  --check-command 'python {project}/check.py' \
  --check-command 'python {project}/check-drawing.py'
```

The public apply transaction passes the assembly and workloads before replacing
the project and keeps a recoverable previous project. Only the new C operation,
its bridge and its consumer compile: all thirteen existing object files are
reused. The six neighboring component implementations and interfaces are
unchanged; five records acquire an additional connected-comparison reference.
The resulting seven-component source project needs ordinary C build tools,
Python and the retained binary assets. It does not need Wine, the original
executable or the lifting toolkit to build/run its portable consumers.

The fifteen new cases cover signed coordinate encodings, exact graphics error
results, source/destination aliasing and mutations to the shared sprite rectangle,
width, selected bank and destination. They also call neighboring font operations
and cleanup. Both x86-64 and AArch64 under QEMU pass these cases and the six
retained asset/font cases. For another architecture, copy the source project
without build outputs/backups, select `CC`/`AR`, and pass `--runner` to both check
scripts. This is a controlled graphics backend, not a portable complete game.

The live recipe exercises actual game objects and DirectDraw, retaining normal
entry and TLS:

```sh
python tests/fixtures/dxball-sprite-drawing/prepare-normal.py \
  /tmp/dx-drawing/sprite-drawing /path/to/game-assets /tmp/dx-drawing-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball sprite-drawing \
  --comparison-package /tmp/dx-drawing-normal/package --output /tmp/dx-drawing-normal-check
```

The selected six components replace twelve entries. Eleven execute during the
recorded startup/input/close probe; opaque drawing is covered by the native
component cases. The first 128 outer graphics calls and 32 metric calls match.
Nested native call counts differ because C can call its own internal helpers;
wall-clock frame counts also differ. Neither these samples nor successful exits
establish matching frames, audio, timing or an entire playthrough. Wine diagnostics
remain separate from application streams. All Wine runs require headless Wayland.
