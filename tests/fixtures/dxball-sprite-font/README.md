# Binary-derived DX-Ball sprite fonts and bank loading

This continues the [cleanup trial](../dxball-cleanup-blind/README.md) with three
ordinary C components: metrics (select/find/measure), rendering
(glyph/line/center), and asset loading. The six-component network implements ten
native entries, shares the existing sprite objects, loads the game's actual
font assets, renders through a graphics service, and releases the same objects.
No original game source or third-party implementation was consulted.

Read [BOUNDARY.md](BOUNDARY.md) and [ASSET-BOUNDARY.md](ASSET-BOUNDARY.md) before
changing the interfaces. The [continuation review](../../../docs/dxball-sprite-continuation.md)
records evidence, the real discrepancy caught, and the resolved Wine-output
capture limitation. The next [drawing continuation](../dxball-sprite-drawing/README.md)
adds sprite drawing and exercises font rendering during actual game execution.

In `nix develop .#lifting`, use the Python interpreter containing the toolkit and
its dependencies consistently for preparation and assembly. These commands assume
it is `python`. Supply the pinned executable, shipped asset directory and a new
output directory; no pilot rebuild is needed:

```sh
python tests/fixtures/dxball-cleanup-blind/prepare.py \
  /path/to/DXBall.exe /tmp/dx-cleanup
python tests/fixtures/dxball-sprite-font/prepare.py \
  /path/to/DXBall.exe /tmp/dx-cleanup/cleanup-clear /tmp/dx-font
spaghetti-headless-wayland python tests/fixtures/dxball-sprite-font/check.py \
  /tmp/dx-font /tmp/dx-font-check
python tests/fixtures/dxball-sprite-font/prepare-assets.py \
  /path/to/DXBall.exe /tmp/dx-font/font-render /path/to/game-assets /tmp/dx-assets
spaghetti-headless-wayland spaghetti-extractor component check dxball sprite-loader \
  --comparison-package /tmp/dx-assets/sprite-loader --output /tmp/dx-assets-check
spaghetti-extractor candidate export dxball --comparison /tmp/dx-assets-check \
  --output /tmp/dx-source/lifted
python tests/fixtures/dxball-sprite-font/assemble.py /tmp/dx-source /tmp/dx-assets-check
make -C /tmp/dx-source
python /tmp/dx-source/check.py
```

The delivered source project needs a C compiler, make, Python's standard library,
and the three copied binary assets. It needs neither the executable nor the
toolkit at build/run time. For another architecture, copy it without build outputs
or retained backup trees, set `CC`/`AR`, and run `check.py --runner /path/to/qemu-aarch64`.
The recorded run passed 20 font cases and six connected asset cases on x86-64
and AArch64. An incremental `candidate apply` also added the loader to the
existing five-component font project, retaining the five source records and
passing the build and workload checks before publishing the update.

To investigate actual game execution, the following ordinary C adapter transports
real native heap objects and calls real native allocator/COM services. It retains
the original entry/TLS, replaces metrics and cleanup, and leaves rendering and
loading native. A separate window controller drives and closes all three sides:

```sh
python tests/fixtures/dxball-sprite-font/prepare-normal.py \
  /tmp/dx-font/font-metrics /path/to/game-assets /tmp/dx-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball font-metrics \
  --comparison-package /tmp/dx-normal/package --output /tmp/dx-normal-check
```

The current public normal-program comparison **passes this bounded integration
probe**. All three processes exit zero, all six selected entry points execute,
and the first 32 retained metric calls agree. Windows application streams are
captured separately from Wine/host diagnostics, which remain in `.host.stderr`
logs. The earlier mixed-stream comparison is retained as a regression reproducer.
No warning filtering or target-specific checker rule is used. Frame/audio
behavior, reproducible input timing and full-game portability remain outstanding;
the partial report is not a complete game comparison.

`probe-startup.py` separately inspects an untouched game with private assets and
requests window closure. Its optional GDI snapshot was black on the retained
Wine/DirectDraw run, so it is not evidence of a correctly rendered frame. All
Wine commands, including controllers and manual probes, require headless Wayland.
