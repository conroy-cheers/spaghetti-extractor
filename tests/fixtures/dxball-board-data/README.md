# DX-Ball board data

[Ordinary C](board.c) replaces five real native entries: collection load/save,
current-board selection/storage, and tile-to-sprite mapping. The
[boundary](BOUNDARY.md) defines a current 20-by-20 byte grid, fifty saved boards,
and explicit file services. It preserves unknown tile bytes, partial I/O and the
native shared file identity. All instruction/data analysis comes from the pinned
executable and its assets; no original source or third-party implementation is
used. The scene previously called “options” in the continuation notes is the
built-in board editor, which consumes these operations alongside gameplay.

Prepare from the retained executable and board asset in the lifting environment:

```sh
python tests/fixtures/dxball-board-data/prepare.py \
  /path/to/DXBall.exe /path/to/Default.bds /tmp/dx-boards
spaghetti-headless-wayland spaghetti-extractor component check dxball board-data \
  --comparison-package /tmp/dx-boards/board-data --output /tmp/dx-boards-check
```

Fourteen cases exercise all five entries, retaining complete current/saved/disk
bytes, surrounding canaries, file identity/liveness and service order. They cover
first/last/middle board indices, failed opens, empty and partial reads/writes,
the actual board asset, all byte-valued tile kinds and unsigned extremes.
Selected original entry bodies remain trapped. Copy indices are in 0..49;
out-of-range native memory corruption is outside this boundary. File effects in
the local comparison are controlled, with live CRT integration checked separately.

Apply to the existing score-screen source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-boards-check --accept-boundary-change board-data \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-board-data/assemble.py {project} /tmp/dx-boards-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py' \
  --check-command 'python check-title.py' \
  --check-command 'python check-scene.py' \
  --check-command 'python check-menu.py' \
  --check-command 'python check-scores.py' \
  --check-command 'python check-screen.py' \
  --check-command 'python check-boards.py'
```

Use an absolute lifting-Python path for assembly if the shell's default Python
lacks its dependencies. The exported project builds without lifting tools or the
original executable. Its checks accept `--runner`, and `CC`/`AR` select a different
architecture. These source consumers do not yet constitute a complete portable
game: editor interaction, remaining gameplay and platform backends still need work.

Install the five entries alongside the existing normal-game network:

```sh
python tests/fixtures/dxball-board-data/prepare-normal.py \
  /tmp/dx-boards/board-data /tmp/dx-screen-normal/package /tmp/dx-boards-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball board-data \
  --comparison-package /tmp/dx-boards-normal/package \
  --output /tmp/dx-boards-normal-check --comparison-timeout 55
```

The live adapter uses the actual CRT and assets, synchronizes byte backing around
each entry, and retains complete board snapshots and tile-map results. It reuses
the counted startup/title/menu/gameplay/close controller. Local and normal workloads
need separate comparison baselines; do not reuse the local result for the different
normal case set. Within either workload, subsequent edits can reuse that workload's
compiled objects. Diagnostics distinguish installed entries from executed entries;
save/store coverage in the local cases does not establish live editor coverage.

See the [continuation record](../../../docs/dxball-board-data-continuation.md)
for retained evidence, timings and remaining scope.
