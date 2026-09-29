# DX-Ball persistent scores

[Ordinary C](scores.c) replaces initialization, loading and ordered insertion of
the fifteen-entry score table. The [boundary](BOUNDARY.md) records the real entry
ranges, file effects, name bounds and lifetime assumptions. The
[shared representation](scores-state.h) names records while retaining all disk
bytes, including little-endian values and bytes after name terminators. Default
names are extracted from the pinned executable; no original game source is used.

From the existing lifting environment:

```sh
python tests/fixtures/dxball-scores/prepare.py \
  /path/to/DXBall.exe /path/to/score.dat /tmp/dx-scores
spaghetti-headless-wayland spaghetti-extractor component check dxball score-table \
  --comparison-package /tmp/dx-scores/score-table --output /tmp/dx-scores-check
```

Twenty cases exercise all three original bodies against the C, with source-side
bodies trapped. They retain initialization and move padding, failed and partial
reads/writes, null opens, access results, equal scores, unsigned extremes, rejected
scores, an unsorted table, empty and maximum-length names, and the retained real
score file. File contents, complete records, call order and handle lifecycle are
observed. The local file service is controlled, and its explicit byte view changes
the actual record backing. The component requires terminated names and does not
claim safe behavior for arbitrary corrupt files.

Apply it to the existing [menu source project](../dxball-menu/README.md):

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-scores-check --accept-boundary-change score-table \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-scores/assemble.py {project} /tmp/dx-scores-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py' \
  --check-command 'python check-pcx.py' \
  --check-command 'python check-title.py' \
  --check-command 'python check-scene.py' \
  --check-command 'python check-menu.py' \
  --check-command 'python check-scores.py'
```

Use an absolute lifting-Python path for assembly if the retained shell selects
another Python. The project builds without the toolkit or original executable.
Use `CC`/`AR` for another architecture and the check scripts' `--runner` option
for QEMU. Prior component implementations and interfaces remain unchanged.

The real-game consumer reuses the existing counted title/menu/gameplay/close
workload and calls the original CRT through ordinary C file adapters:

```sh
python tests/fixtures/dxball-scores/prepare-normal.py \
  /tmp/dx-scores/score-table /tmp/dx-menu-normal/package /tmp/dx-scores-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball score-table \
  --comparison-package /tmp/dx-scores-normal/package --output /tmp/dx-scores-normal-check \
  --comparison-timeout 55
```

The consumer's shared C type headers are explicit include inputs. Startup invokes
initialization and loading; this workload does not reach score entry or save a
new score. Those paths have local native evidence and remain to be exercised
through the score-screen consumer. The standalone project contains subsystem
consumers, while the actual game still uses remaining native scene/gameplay and
platform code. See the [continuation record](../../../docs/dxball-scores-continuation.md).
