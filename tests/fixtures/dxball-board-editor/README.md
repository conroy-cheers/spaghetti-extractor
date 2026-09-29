# DX-Ball board editor

[The C implementation](editor.c) covers seven real entries: enter, redraw, update,
key dispatch, palette rendering, status rendering and leave. It reuses the board
storage, scene, font and graphics interfaces. [The boundary](BOUNDARY.md) describes
shared byte backing, synchronous callbacks, hit regions and retained target
services. Authoring used executable instructions/data and assets, without original
game sources or third-party implementations.

In the retained lifting environment, prepare from the local menu and board packages:

```sh
python tests/fixtures/dxball-board-editor/prepare.py \
  /path/to/DXBall.exe /tmp/dx-menu/menu-scene /tmp/dx-boards/board-data /tmp/dx-editor
spaghetti-headless-wayland spaghetti-extractor component check dxball board-editor \
  --comparison-package /tmp/dx-editor/board-editor --output /tmp/dx-editor-check
```

Sixteen cases match the original x86 entry bodies. They cover continuous paint,
erase, palette selection, strict board edges, signed cursor clamps, exact input
flags, a callback changing the input and board index, board navigation/clamping,
low-byte keyboard codes, file failures, partial reads and the retained board file.
Every editor entry and all five board operations execute. Full current/saved board
bytes, hit regions, file state, text, service order, pixels and object lifetimes
are observed. The local bank includes the palette's real slot range in addition
to the inherited font fixture's glyphs. Selected original bodies remain trapped.

Graphics/file services here are controlled. Native board rendering, hit-region
helpers and cursor behavior remain separate target dependencies; local comparisons
do not make them additional lifted entries or establish a complete portable game.

The real editor's clear/save workflow declares `Default.bds` mutable and compares
its saved bytes through the normal-program runner:

```sh
python tests/fixtures/dxball-board-editor/prepare-save-workload.py \
  /tmp/dx-boards-normal/package /tmp/dx-editor-save
spaghetti-headless-wayland spaghetti-extractor component check dxball board-data \
  --comparison-package /tmp/dx-editor-save/package \
  --output /tmp/dx-editor-save-check --comparison-timeout 55
```

This prerequisite probe keeps the previous sixteen-component network; it does not
select the new editor C. Its controller enters the editor using Ctrl+F1, clears
the current board with Backspace, saves with S and closes. It uses ordinary window
messages and read-only memory checks, with no writes to application code/data or
files. The untouched original, instrumented original and selected source network
all exit zero and save identical board data. Exact saved files and their
presence/content observations are retained with the comparison result. The input
package remains unchanged. The earlier runner rejection of legitimate saves is
resolved by this general mutable-file declaration.

Apply the locally checked editor to a copy of the existing board-data source
project, then check the connected source consumers:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-editor-check --accept-boundary-change board-editor \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-board-editor/assemble.py {project} /tmp/dx-editor-check' \
  --check-command 'make -j2' --check-command 'python check-editor.py'
```

The retained integration also runs every preceding consumer check. All 201 cases
match on x86-64 and AArch64. The source project now contains seventeen components
implementing 63 native entries, with all sixteen neighboring identities and all
43 prior compiled objects unchanged.

Select the new editor in the actual save workload with the existing public
package-revision API:

```sh
python tests/fixtures/dxball-board-editor/prepare-normal.py \
  /tmp/dx-editor/board-editor /tmp/dx-editor-save/package /tmp/dx-editor-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball board-editor \
  --comparison-package /tmp/dx-editor-normal/package \
  --output /tmp/dx-editor-normal-check --comparison-timeout 55
```

This preparation explicitly reviews the controlled-to-live boundary handoff.
It retains the existing native file/render/input services and shares the same
editor, board, menu and scene state across callbacks. The real workload matches
with seven outer editor state/region/board/pixel observations and identical saved
files. No editor C correction was needed. The local cases cover interactions
outside that workload, including leave and rendering-induced input changes;
the live run is not a substitute for them. Any newly discovered semantic
discrepancy must get a local reproducer without the full application workflow.

A first source shutdown timeout in the earlier prerequisite probe remains
recorded; its identical replay passes. The editor integration itself passes
on its first execution. Remaining target helpers, gameplay, startup and portable
platform backends still need lifting.
See the [continuation record](../../../docs/dxball-board-editor-continuation.md).
