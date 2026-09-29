# DX-Ball PCX images and palettes

The [ordinary C decoder](pcx.c) replaces three native operations using buffered
file services, live graphics storage and shared palettes. Its
[boundary](BOUNDARY.md) records the pinned executable, exact entry ranges,
ownership and deliberately preserved decoder quirks. Only the executable,
disassembly, shipped assets and existing operator-authored interfaces were used.

Use the Python and tools from `nix develop .#lifting`:

```sh
python tests/fixtures/dxball-pcx/prepare.py \
  /path/to/DXBall.exe /path/to/game-assets /tmp/dx-pcx
spaghetti-headless-wayland spaghetti-extractor component check dxball pcx-image \
  --comparison-package /tmp/dx-pcx/pcx-image --output /tmp/dx-pcx-check
```

Twenty cases compare the real machine bodies against C. They cover all five
shipped images, clipping, malformed/short inputs, zero-length and overshooting
runs, lock retries, changed descriptor fields and palette callback writes.
Observations include the complete pixel storage with padding/guards, both
palettes, buffered-file consumption and ordered service calls. The source side
traps the selected native bodies. The file adapter owns backing storage and
exposes its cursor/count; it does not replace decoding with expected pixels.

Extend the [game-flow source project](../dxball-game-flow/README.md) through the
public transaction:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-pcx-check --accept-boundary-change pcx-image \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-pcx/assemble.py {project} /tmp/dx-pcx-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py'
```

The assembly recipe needs the lifting Python with `pefile` and the toolkit.
Pass its absolute interpreter path if a retained shell exposes a different
`python`. The resulting source project needs only C, standard Python and assets;
it has no Wine or original executable dependency. `CC`/`AR` choose another
architecture; the check scripts accept `--runner /path/to/qemu-aarch64`.

For a local edit, reopen the comparison:

```sh
spaghetti-extractor component start dxball pcx-image \
  --comparison-result /tmp/dx-pcx-check --output /tmp/dx-pcx-edit
spaghetti-headless-wayland spaghetti-extractor component check dxball pcx-image \
  --comparison-package /tmp/dx-pcx-edit --case literal-none \
  --reuse-comparison /tmp/dx-pcx-check --output /tmp/dx-pcx-edited-check
```

Changing the decoder's `<= limit` condition to `< limit` produces a real
difference: file position 140 instead of 141, and a missing pixel. One translation
unit rebuilds and two are reused. Restore the condition to obtain a match again.

For actual game execution, reuse the game-flow normal-program package and its
counted-input controller:

```sh
python tests/fixtures/dxball-pcx/prepare-normal.py \
  /tmp/dx-pcx/pcx-image /tmp/dx-flow-normal/package /tmp/dx-pcx-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball pcx-image \
  --comparison-package /tmp/dx-pcx-normal/package --output /tmp/dx-pcx-normal-check \
  --comparison-timeout 55
```

The native adapter preserves actual CRT buffers across refill/seek/close and the
complete DirectDraw descriptor across lock retries. Pixel storage remains valid
only through unlock. Normal execution observes image/palette hashes after calls;
the additional read lock assumes quiescent eight-bit surfaces. Local cases compare
full bytes. The bounded live probe is not an arbitrary playthrough or proof of
frame/audio equivalence. Existing scene bodies and platform services remain
native; the portable source consumers are still subsystems of the full game.

See the [continuation record](../../../docs/dxball-pcx-continuation.md) for results,
neighbor reuse, measured costs and remaining work. All Wine runs use headless
Wayland, with application streams separated from host diagnostics.
