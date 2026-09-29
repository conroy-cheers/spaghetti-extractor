# DX-Ball main menu

[Ordinary C](menu.c) replaces the seven existing menu entry points: enter,
redraw, update, key, leave, initialize dots and animate. The
[boundary](BOUNDARY.md) records actual native ranges and service assumptions.
The [shared object](menu-state.h) extends the existing scene, animation, font,
palette and flow objects with score, clock and dot storage. The dot mask and
display text are recovered from the pinned executable; no original game source
is used. The leave function is also used by scene 3 and has one replacement.

Reuse the [title-scene package](../dxball-title-scene/README.md) and retained
compiler environment:

```sh
python tests/fixtures/dxball-menu/prepare.py \
  /path/to/DXBall.exe /tmp/dx-scene/title-scene /tmp/dx-menu
spaghetti-headless-wayland spaghetti-extractor component check dxball menu-scene \
  --comparison-package /tmp/dx-menu/menu-scene --output /tmp/dx-menu-check
```

Twelve cases exercise every entry, including unsigned score formatting, exact
text spans, signed cursor coordinates, key low-byte handling, conditional cleanup,
elapsed-clock branches, clock wrap and a failed pixel lock followed by success.
Original bodies are trapped on the source side. Observations retain dot/offset
arrays, shared fields, palette storage, pixels, text and service interactions.
Local file, audio and graphics services are controlled; fonts, sprite drawing and
cleanup use the existing connected C components. The larger memory boundary
identifies an older cleanup canary as an alias of the final menu offset word.

Apply the checked component to the existing title-scene source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-menu-check --accept-boundary-change menu-scene \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-menu/assemble.py {project} /tmp/dx-menu-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py' \
  --check-command 'python check-title.py' \
  --check-command 'python check-scene.py' \
  --check-command 'python check-menu.py'
```

Use an absolute lifting-Python path in the assembly command if needed. The
exported project builds ordinary C without lifting tools or the original binary.
`CC`/`AR` select compilers; check scripts accept `--runner /path/to/qemu-aarch64`.
The source project contains subsystem consumers with controlled platform services;
it becomes a portable game only after remaining bodies and backends are lifted.

For actual game execution, reuse the title-scene live package:

```sh
python tests/fixtures/dxball-menu/prepare-normal.py \
  /tmp/dx-menu/menu-scene /tmp/dx-scene-normal/package /tmp/dx-menu-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball menu-scene \
  --comparison-package /tmp/dx-menu-normal/package --output /tmp/dx-menu-normal-check \
  --comparison-timeout 55
```

The existing public requirement-refinement API switches `scene-consumer` to the
live contract. Actual file, graphics, clock and audio calls use ordinary adapters,
with menu state transported around reentrant calls. The existing counted-input
controller is unchanged. Outer menu observations include dot/offset backing and
pixel/palette hashes; absolute clock inputs are retained separately as diagnostics.
All resulting state and pixel effects still compare. Menu key and leave reason
zero are covered locally but not by this live click-to-gameplay sequence. Neither
the finite cases nor this sequence establish a full playthrough or audio equality.

See the [continuation record](../../../docs/dxball-menu-continuation.md).
