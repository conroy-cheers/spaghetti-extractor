# DX-Ball gameplay frame

[play.c](play.c) lifts the native `0x4044d0` frame routine into ordinary C. It
sequences physics/rendering services and directly implements shared ball/shot
iteration, pending-event disposal, score effects, powerup adjustments and input
handling. [BOUNDARY.md](BOUNDARY.md) records storage, alias, lifetime and numeric
premises. Helper bodies remain separate work; this is not a complete gameplay
or platform implementation.

Preparation uses the executable and established shared menu headers:

```sh
python tests/fixtures/dxball-gameplay/prepare.py \
  /path/to/DXBall.exe /tmp/dx-menu/menu-scene /tmp/dx-play
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-play/gameplay-frame --output /tmp/dx-play-check
```

Sixteen local cases execute the actual original frame without game startup or
neighboring bodies. They compare ordered interactions, shared scalar state,
complete list payloads/links, cursors, free-event lifetime observations and pending
cell bytes. Coverage includes pause, multi-frame sequences, callback cursor
changes, disposal callbacks, powerups, signed flags, mouse input and binary64
velocity rounding. Source-side interception replaces the complete frame body.

The original unlinks an event and then advances its cursor again; an intervening
event can remain pending. A local editing exercise detects changing that behavior:

```sh
spaghetti-extractor component start dxball gameplay-frame \
  --comparison-result /tmp/dx-play-check --output /tmp/dx-play-edit
# In source/play.c, replace the body of next_event with:
# return events->current != NULL;
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-play-edit --reuse-comparison /tmp/dx-play-check \
  --case connected-lists --output /tmp/dx-play-wrong
```

The retained observations expose the changed cursor and interaction sequence.
Restore the original iterator body and recheck. This diagnosis does not require
the game UI, and only the edited C unit needs recompilation.

The integration drawing discrepancy also has a small connected consumer:

```sh
python tests/fixtures/dxball-gameplay/prepare-paddle.py \
  /tmp/dx-play/gameplay-frame /path/to/Mball2.sbk /tmp/dx-paddle
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-paddle/package --output /tmp/dx-paddle-check
```

This executes the real native paddle helper under either frame, without game
startup or DirectDraw. Retained asset dimensions, fixed clock inputs and all four
random choices produce exact drawing/mark observations. To reproduce the original
450-versus-449 mismatch, copy the package and change the random provider in
`headers/frame-runtime.c` from `(mode-16)%4` to
`(mode-16+(entered!=0))%4`; check only `--case paddle-random-0`. The first difference
is the random result (0 versus 1), before the rectangle difference. Restore the
provider to compare the implementations under corresponding inputs. This is an
intentional negative harness check, not a replacement implementation defect.

Apply to a copy of the preceding region source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-play-check --accept-boundary-change gameplay-frame \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-gameplay/assemble.py {project} /tmp/dx-play-check' \
  --check-command 'make -j2' --check-command 'python check-play.py'
```

The standalone `play` consumer needs ordinary C and standard Python, without the
game, Wine or lifting tools. `check-play.py --runner /path/to/qemu-aarch64` also
checks a cross build. Assembly itself uses the lifting Python environment.

For the separate normal-game integration check:

```sh
python tests/fixtures/dxball-gameplay/prepare-normal.py \
  /tmp/dx-play/gameplay-frame /tmp/dx-regions-normal/package /tmp/dx-play-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-frame \
  --comparison-package /tmp/dx-play-normal/package \
  --output /tmp/dx-play-normal-check --comparison-timeout 55
```

This reuses the established counted input driver, original physics/allocation
services and existing C component network. Live views refresh complete reachable
records around synchronous calls. The observer retains frame state, live lists,
pending cells and pixel hashes; absolute clock readings remain diagnostics.
Previously borrowed objects are not read after they leave the native roots.
The paddle helper receives an explicit clock/random input schedule on both
observed sides; the input trace is compared as well. Other services retain their
actual environment. Untouched original execution checks startup, output and exit;
it does not establish equality of pixels produced under uncontrolled random inputs.

The compiler-backed practical source profile accepts this C. The optional formal
source profile reports `restricted_c_volatile_storage` for the explicit binary64
rounding locals; no strong qualification is claimed. This does not prevent local
comparison, source assembly or portable execution. Future integration discoveries
must become local or connected regressions; inability to express them locally is
a tooling gap. Exact results and remaining work are in the
[continuation record](../../../docs/dxball-gameplay-continuation.md).
