# DX-Ball frame and scene control

This binary-derived component lifts frame updates, scene entry/exit, key dispatch,
redraw, surface recovery and shutdown. Its [ordinary C](flow.c) uses explicit
[shared state](flow-state.h) and synchronous scene/platform services. The
[boundary](BOUNDARY.md) records exact native entries and admitted behavior.
No original DX-Ball source or new checker/compiler machinery is involved.

Use the Python and tools from `nix develop .#lifting`. Start with the
[sprite lifecycle package and source project](../dxball-sprite-lifecycle/README.md):

```sh
python tests/fixtures/dxball-game-flow/prepare.py \
  /path/to/DXBall.exe /tmp/dx-lifecycle/sprite-lifecycle /tmp/dx-flow
spaghetti-headless-wayland spaghetti-extractor component check dxball game-flow \
  --comparison-package /tmp/dx-flow/game-flow --output /tmp/dx-flow-check
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-flow-check --accept-boundary-change game-flow \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-game-flow/assemble.py {project} /tmp/dx-flow-check' \
  --check-command 'make -j2' \
  --check-command 'python check.py' \
  --check-command 'python check-drawing.py' \
  --check-command 'python check-lifecycle.py' \
  --check-command 'python check-flow.py'
```

The assembly command must use the lifting environment's Python, with `pefile` and
the toolkit available. A retained shell may also expose another `python`; pass
the full interpreter path in `--assembly-command` in that situation. The exported
check scripts require only standard Python. The resulting standalone consumers
use C, asset files and their controlled backends; they do not need Wine, the
original executable or the toolkit. Set `CC`/`AR` for another architecture and
pass `--runner /path/to/qemu-aarch64` to each check script.

Thirty-two new cases cover all five scene IDs, out-of-range words, initialization,
pending transitions, callback mutation, audio restoration, exact surface-lost
status, recovery failures, windowed/fullscreen refresh rules and shutdown.
Recovery executes the existing sprite restoration and loader with real bank
files. Observations retain state, identities, pixels, ordered calls and cleanup.
The source side traps all eight selected native entry bodies.

To exercise the local edit loop, reopen a result:

```sh
spaghetti-extractor component start dxball game-flow \
  --comparison-result /tmp/dx-flow-check --output /tmp/dx-flow-edit
```

In `source/flow.c`, moving the transition flag clear before scene entry introduces
a real callback-ordering error. The `scene-0-mode-2` case reports
`$.flow.after_frame[3]`: original zero, edited C nine. Checking this edit rebuilds
one translation unit and reuses sixteen. Restore the C and rerun the case; it
matches again. No neighboring implementation or boundary needs an edit.

For normal game execution, supply the retained lifecycle normal-program package,
drawing package and original runtime assets:

```sh
python tests/fixtures/dxball-game-flow/prepare-normal.py \
  /tmp/dx-flow/game-flow /tmp/dx-lifecycle-normal/package \
  /tmp/dx-drawing/sprite-drawing /path/to/game-assets /tmp/dx-flow-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball game-flow \
  --comparison-package /tmp/dx-flow-normal/package --output /tmp/dx-flow-normal-check \
  --comparison-timeout 55
```

The external controller uses a hardware breakpoint at frame entry, VA `40ab10`,
then waits at that invocation's return address before counting another frame.
It sends ordinary key/mouse/close messages at counted updates and never patches
application code or data. Waiting for the outer return avoids counting an
observer wrapper's nested original-body call twice. The former call-site probe
inside WinMain stopped working when WinMain was lifted; this boundary works
with either caller implementation. The same controller drives all three sides, including the
untouched executable. Debugger pauses still affect wall clocks; this is a bounded
input protocol, not general deterministic replay. Unexpected application
breakpoints remain exceptions, including traps in selected native bodies.

Normal execution uses actual native scene, allocation, graphics and audio
services. The retained startup/menu/gameplay/close case matches control, metrics,
graphics and lifecycle observations; selected-entry counters show which C
operations executed. Wine diagnostics remain in `.host.stderr`, separate from
application bytes; `runtime-SIDE/tmp/controller.log` retains the input schedule.
The source project is still a subsystem, not a portable complete game. See the
[continuation record](../../../docs/dxball-game-flow-continuation.md).
