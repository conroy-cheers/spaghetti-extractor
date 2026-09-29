# DX-Ball paddle movement and drawing

[paddle.c](paddle.c) lifts the actual movement and drawing entries using the
pinned executable's instructions and data, without original game source.
[BOUNDARY.md](BOUNDARY.md) records the shared objects, callback effects, integer
arithmetic and floating-point assumptions. Paddle size, position, sprite and
powerup flags retain their existing owners in the pickup/motion/gameplay network.
The component owns only five animation and spark fields.

Prepare and compare the native entry bodies without game startup:

```sh
python tests/fixtures/dxball-paddle/prepare.py \
  /path/to/DXBall.exe /tmp/dx-pickups-check/inputs /tmp/dx-paddles
spaghetti-headless-wayland spaghetti-extractor component check dxball paddle-control \
  --comparison-package /tmp/dx-paddles/paddle-control --output /tmp/dx-paddles-check
```

Twenty-one scenarios cover signed clamping, windowed/fullscreen behavior,
animation phases, both powerup flags, spark deadlines, all random variants,
binary64 crop rounding, bank aliases and changes made by every service callback.
A twelve-step case combines movement and drawing. Observations include borrowed
state, sprite payloads, surface identities, bank aliases and ordered graphics,
cursor, clock and damage interactions. Services are controlled; the local fixture
does not start the game or require its graphics backend.

Connect the existing gameplay frame and pickup components:

```sh
python tests/fixtures/dxball-paddle/prepare-frame.py \
  /tmp/dx-paddles/paddle-control /tmp/dx-frame-check/inputs \
  /tmp/dx-pickups-check/inputs /tmp/dx-paddle-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball paddle-control \
  --comparison-package /tmp/dx-paddle-frame/package --output /tmp/dx-paddle-frame-check
```

Four eight-frame cases cover growth, shrinking, the tiny-paddle pickup and
windowed movement. The actual frame calls movement and drawing; actual pickup
collection changes the shared width and calls movement again. Other helpers are
controlled. All three components use the same shared objects, without game startup.

Apply to a copy of the preceding particle source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-paddles-check --accept-boundary-change paddle-control \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-paddle/assemble.py {project} /tmp/dx-paddles-check /tmp/dx-paddle-frame-check' \
  --check-command 'make -j2' --check-command 'python check-paddles.py' \
  --check-command 'python check-paddle-frame.py'
```

These source consumers use ordinary C and Python without Wine or the game.
Their check scripts accept `--runner /path/to/qemu-aarch64` for cross builds.
Unchanged component records, compiled objects and consumer evidence are reused.

Select the paddle C in the existing normal-game comparison:

```sh
python tests/fixtures/dxball-paddle/prepare-normal.py \
  /tmp/dx-paddles/paddle-control /tmp/dx-particles-normal-check/inputs /tmp/dx-paddles-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball paddle-control \
  --comparison-package /tmp/dx-paddles-normal/package \
  --output /tmp/dx-paddles-normal-check --comparison-timeout 90
```

This retains the existing 64-frame launch/close workload, seed, paddle inputs and
palette-clock schedule. It selects the preceding twenty-five components and
retains their observations. Cursor and DirectDraw calls use the real services;
the existing sprite and damage components remain selected. Local and connected
cases independently cover callback and resize behavior the normal workload may
not reach. Any semantic integration discrepancy must become a retained local or
small connected regression. Inability to express it is a tooling gap; finite
comparisons cannot rule out all previously unseen cases.
