# DX-Ball title animation

The [ordinary C](title.c) replaces four existing title-screen functions: text
scrolling, sine-wave blits, wobbling strips and palette cycling. Shared
[state](title-state.h) uses the existing font, palette and flow layouts. The
[boundary](BOUNDARY.md) records exact native entries, buffer lifetimes and numeric
assumptions. No original DX-Ball source is used.

Use the lifting environment and the existing
[sprite-drawing package](../dxball-sprite-drawing/README.md):

```sh
python tests/fixtures/dxball-title-animation/prepare.py \
  /path/to/DXBall.exe /tmp/dx-drawing/sprite-drawing /tmp/dx-title
spaghetti-headless-wayland spaghetti-extractor component check dxball title-animation \
  --comparison-package /tmp/dx-title/title-animation --output /tmp/dx-title-check
```

Eighteen cases execute three rounds of all four operations against the real
machine bodies. They cover missing glyphs, signed phases, endpoint table samples,
palette widths, windowed behavior, byte wrapping and callbacks changing objects
or palette state. Full backing pixels and palettes, ordered blits and state are
compared. Font metrics/rendering and destination selection use the existing
components. The source side traps the selected original bodies.

Extend the [PCX source project](../dxball-pcx/README.md):

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-title-check --accept-boundary-change title-animation \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-title-animation/assemble.py {project} /tmp/dx-title-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py' \
  --check-command 'python check-title.py'
```

Use the lifting Python, including `pefile` and the toolkit, for the assembly
recipe. An absolute interpreter path avoids another `python` in a retained
shell. The delivered consumers build from C and assets without Wine, the original
executable or lifting tools. Set `CC`/`AR` for another architecture and pass
`--runner /path/to/qemu-aarch64` to each check script.

For actual game execution, reuse the PCX normal-program package:

```sh
python tests/fixtures/dxball-title-animation/prepare-normal.py \
  /tmp/dx-title/title-animation /tmp/dx-pcx-normal/package /tmp/dx-title-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball title-animation \
  --comparison-package /tmp/dx-title-normal/package --output /tmp/dx-title-normal-check \
  --comparison-timeout 55
```

The normal adapter borrows the actual initialized message and sine table, calls
the existing font/drawing replacements and operates on real DirectDraw surfaces.
Both instrumented sides take additional read locks to hash visible backing and
display pixels. The unchanged counted-input controller also runs the untouched
original. This is a bounded startup/menu/gameplay/close workload, not a complete
portable game or arbitrary playthrough qualification. See the
[continuation record](../../../docs/dxball-title-animation-continuation.md).
