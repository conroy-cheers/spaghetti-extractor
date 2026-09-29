# DX-Ball hit regions

[regions.c](regions.c) translates the actual reset, rectangle-definition and
hit-test entries using a borrowed view of the editor's existing region table.
[BOUNDARY.md](BOUNDARY.md) records exact storage, signed-coordinate, sentinel and
lifetime premises. Authoring uses the pinned executable and existing object
declarations; it does not use the original game source or new tool internals.

Prepare from the established editor package (only its shared headers are read):

```sh
python tests/fixtures/dxball-regions/prepare.py \
  /path/to/DXBall.exe /tmp/dx-editor/board-editor /tmp/dx-regions
spaghetti-headless-wayland spaghetti-extractor component check dxball hit-regions \
  --comparison-package /tmp/dx-regions/hit-regions --output /tmp/dx-regions-check
```

Nine local scenarios execute the real original entries without the game UI or
neighboring component bodies. They retain every table record, count, guard word,
argument and result after each call. Cases cover editor geometry, reset framing
and wrap, signed coordinates, overlapping inclusive edges, arbitrary enable
words, inverted rectangles, count boundaries and generated geometry.

To exercise local diagnosis, reopen the result with `component start` and change
`hit = i;` in `source/regions.c` to `return i;`:

```sh
spaghetti-extractor component start dxball hit-regions \
  --comparison-result /tmp/dx-regions-check --output /tmp/dx-regions-edit
# Edit /tmp/dx-regions-edit/source/regions.c, then:
spaghetti-headless-wayland spaghetti-extractor component check dxball hit-regions \
  --comparison-package /tmp/dx-regions-edit --reuse-comparison /tmp/dx-regions-check \
  --case overlapping-edges --output /tmp/dx-regions-wrong
```

The original returns the last matching region. This edit returns the first;
the local observation identifies the differing result. Restore the assignment
and check again. No game session is needed to detect this behavior.

Apply to a copy of the preceding damage source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-regions-check --accept-boundary-change hit-regions \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-regions/assemble.py {project} /tmp/dx-regions-check' \
  --check-command 'make -j2' --check-command 'python check-regions.py' \
  --check-command 'python check-editor.py'
```

The existing editor now calls the checked region component through its borrowed
table, preserving its native-derived expectations. The separate direct consumer
and the connected editor consumer need ordinary C and standard Python, without
Wine, the original executable or game UI. Check scripts accept
`--runner /path/to/qemu-aarch64`. Assembly uses the lifting Python environment;
the generated source project does not need it.

For the separate normal-program integration check:

```sh
python tests/fixtures/dxball-regions/prepare-normal.py \
  /tmp/dx-regions/hit-regions /tmp/dx-damage-normal/package /tmp/dx-regions-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball hit-regions \
  --comparison-package /tmp/dx-regions-normal/package \
  --output /tmp/dx-regions-normal-check --comparison-timeout 55
```

This keeps preceding editor, board, rendering, damage and saved-file observations,
and adds complete region records. New integration findings must become local or
small connected regressions. Inability to represent them locally is a tooling
gap; passing finite cases is not a universal guarantee. See the
[continuation record](../../../docs/dxball-regions-continuation.md) for exact
retained results and remaining game/platform work.
