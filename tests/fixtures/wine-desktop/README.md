# Candidate desktop workloads

`run.py` launches one candidate binary in a fresh owned Wine prefix, using the
existing standard-handle capture and Wine-session lifecycle. Run it inside
`spaghetti-headless-wayland`. It has no original/replacement roles or application
image addresses. Supply a binary, assets directory and an ordinary message script:

```sh
spaghetti-headless-wayland python tests/fixtures/wine-desktop/run.py \
  candidate.exe actions.txt /tmp/desktop-run --assets /path/to/assets \
  --compiler i686-w64-mingw32-gcc --wine wine --server wineserver
```

The output directory must be fresh. Assets are copied, then the selected image is
installed as `candidate.exe`. Keep unrelated executables out of the asset input.
`--env NAME=VALUE` supplies application/environment inputs. `--timeout` bounds
execution; private prefixes are stopped and disposed, with inputs/logs retained.

The script supports these sequential actions:

| Action | Meaning |
| --- | --- |
| `wait 1000` | Wait milliseconds; early candidate exit is a failure. |
| `message 256 113 0` | Post a Win32 message with decimal message/wParam/lParam. |
| `move 320 240` | Call SetCursorPos in desktop coordinates. |
| `capture frame.bmp` | Capture the window client DC through GDI. |
| `snapshot frame.png` | Request a compositor desktop image and wait for its completion. Requires `--capture` on the headless runner. |

For compositor snapshots, launch the same command with
`spaghetti-headless-wayland --capture python ...`. The private desktop enables
Weston's capture protocol and exposes `spaghetti-desktop-capture OUTPUT.png` to
the host controller. Neither candidate binary needs hooks or modifications.
Names in `snapshot` must be PNG basenames; existing images are not overwritten.
The driver waits for a host acknowledgement before the next action, while the
application continues running. Missing capability, capture failure and timeout
fail the workload and retain diagnostics, rather than producing a passing blank
observation. This observes wall-clock presentation, not a deterministic frame.

Images are retained under `captures/`; `result.json` records their sizes, hashes
and the driver's `client_rect` (x, y, width, height in **Win32 screen coordinates**).
Those coordinates need not match compositor pixels under Wine virtual fullscreen.
Retain the full image and define any comparison region explicitly in compositor
coordinates; do not silently crop using Win32 geometry. `logs/snapshot-*` contains
host capture diagnostics, separate from application streams. Capture is opt-in
and confined to the owned headless desktop. Its capability path remains a runtime
input and is withheld from C compilation, preserving eligible object reuse.

The driver finds the first visible, unowned top-level window in the launched
process, records its class/title, and requests WM_CLOSE after the actions.
Multi-process launchers or selecting among multiple application windows need a
further explicit selection facility. This is a small normal-execution driver,
not a deterministic application scheduler. Hold buttons across sampling frames.
GDI captures may omit DirectDraw/GPU presentation; black captures must not count
as visual equivalence. Compositor snapshots observe final desktop presentation.
Frame-specific comparisons still use their declared
component/consumer observations.

`runtime/desktop-driver.json` and `desktop-driver.log` record controller results;
they do not share the candidate's observed streams. `logs/execution.stdout` and
`.stderr` are application streams, `.trace` is instrumentation, and `.host.*`
contains Wine diagnostics. Weston/Xwayland and audio-server logs are also copied
before cleanup. A successful process exit does not establish behavioral equality.

Weston's headless virtual input seat is required: without `--fake-seat`, the
retained DX-Ball cursor workload crashed Xwayland in `xwl_cursor_warped_to` for
both binaries. The shared environment enables that seat and its Nix check warps
and queries the cursor directly through X11, without a target or Wine prefix.
