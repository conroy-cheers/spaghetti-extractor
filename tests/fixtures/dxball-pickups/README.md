# DX-Ball pickup lifecycle

[pickup.c](pickup.c) implements creation, movement/collection, drawing and removal
from the four actual native entries. It uses the existing motion, frame and
sprite views, with an explicit list and sixteen ordinary service interfaces.
[BOUNDARY.md](BOUNDARY.md) records the admitted memory/lifetime domain and native
quirks. Authoring used executable instructions/data, without original game source.

Prepare and check without game startup:

```sh
python tests/fixtures/dxball-pickups/prepare.py \
  /path/to/DXBall.exe /tmp/dx-motion-check/inputs /tmp/dx-pickups
spaghetti-headless-wayland spaghetti-extractor component check dxball pickup-lifecycle \
  --comparison-package /tmp/dx-pickups/pickup-lifecycle --output /tmp/dx-pickups-check
```

Twenty-two scenarios exercise every emitted/collected kind, the rare random
gates, particle modes, movement bounds, resizing, callbacks, list removal and
generated sequences. Observations include complete live pickup payloads/links,
allocation/free identity, shared flags/counters, sprite contents/aliases, board
bytes and ordered service effects.

Connect the existing frame as an actual caller:

```sh
python tests/fixtures/dxball-pickups/prepare-frame.py \
  /tmp/dx-pickups/pickup-lifecycle /tmp/dx-frame-check/inputs /tmp/dx-pickup-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball pickup-lifecycle \
  --comparison-package /tmp/dx-pickup-frame/package --output /tmp/dx-pickup-frame-check
```

Five four-frame consumers exercise collection, resizing, disposal, motion and
creation from the frame's event queue. Both original and C execution share the
same views; other services are controlled and observed. No graphics backend or
full application workflow is required.

Apply to a copy of the preceding brick source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-pickups-check --accept-boundary-change pickup-lifecycle \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-pickups/assemble.py {project} /tmp/dx-pickups-check /tmp/dx-pickup-frame-check' \
  --check-command 'make -j2' --check-command 'python check-pickups.py' \
  --check-command 'python check-pickup-frame.py'
```

These portable consumers require ordinary C and Python at runtime. The checks
accept `--runner /path/to/qemu-aarch64` for a cross build. Existing components,
compiled objects and unaffected consumer evidence remain reusable.

The independent normal-game comparison adds the C pickup implementation to the
existing brick/frame/motion network through real services:

```sh
python tests/fixtures/dxball-pickups/prepare-normal.py \
  /tmp/dx-pickups/pickup-lifecycle /tmp/dx-bricks-normal/package /tmp/dx-pickups-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball pickup-lifecycle \
  --comparison-package /tmp/dx-pickups-normal/package \
  --output /tmp/dx-pickups-normal-check --comparison-timeout 55
```

This retains the preceding 64-frame launch/close driver and explicit random,
paddle and palette inputs, including their observations. Pixels, palettes and
parent state remain compared. Local and connected cases separately cover
collection variants and disposal. See the [continuation](../../../docs/dxball-pickups-continuation.md)
for exact evidence and unfinished full-game/platform work.
