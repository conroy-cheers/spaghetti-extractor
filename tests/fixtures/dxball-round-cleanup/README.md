# DX-Ball round cleanup and gameplay departure

[round.c](round.c) lifts native clear and scene leave in 65 lines of C. Five
private native removal helpers become typed private C functions. Authoring used
the pinned executable instructions/data, without the original game source.
[BOUNDARY.md](BOUNDARY.md) records the shared objects, disposal order, callback
effects and finite comparison domain.

The component borrows existing progression, powerup, particle and explosion
state. It uses seven existing record types across nine lists. It starts disposal
at each list's current cursor, which need not be its head, and rereads the cursor
after each free callback. Existing payloads, aliases, roots and counters remain
observable. Six services expose free, fade, surface clearing, sound/sprite release
and music stop; platform behavior remains outside this boundary.

Prepare and compare without starting the game:

```sh
python tests/fixtures/dxball-round-cleanup/prepare.py \
  /path/to/DXBall.exe /tmp/dx-progress-check/inputs /tmp/dx-round
spaghetti-headless-wayland spaghetti-extractor component check dxball round-cleanup \
  --comparison-package /tmp/dx-round/round-cleanup --output /tmp/dx-round-check
```

The 28 cases cover empty/single/multiple lists, head/middle/tail/null cursors,
individual object kinds, callback-driven cancellation, redirection and extension,
repopulation of earlier lists, retained counters and payloads, repeated cleanup,
generated layouts, and partial/full scene leave. Ordered service arguments and
complete controlled state are compared before and after callbacks.

Connect the actual progression implementation:

```sh
python tests/fixtures/dxball-round-cleanup/prepare-connected.py \
  /tmp/dx-round/round-cleanup /tmp/dx-progress-check/inputs /tmp/dx-round-connected
spaghetti-headless-wayland spaghetti-extractor component check dxball round-cleanup \
  --comparison-package /tmp/dx-round-connected/package --output /tmp/dx-round-connected-check
```

Four cases run actual transitions and cleanup over the same objects: restart
twice, an existing score-scene request, last-life game over, and a free callback
that changes the caller's game-over decision. The restart case disposes all nine
lists, creates a ball, then disposes it on the next round transition. Remaining
rendering, sound and allocation services are controlled and observed. No full
startup or UI automation is required.

Apply to a copy of the preceding progression source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-round-check --accept-boundary-change round-cleanup \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-round-cleanup/assemble.py {project} /tmp/dx-round-check /tmp/dx-round-connected-check' \
  --check-command 'make -j2' --check-command 'python check-round-cleanup.py' \
  --check-command 'python check-round-connected.py'
```

The source consumers run without Wine and accept `--runner /path/to/qemu-aarch64`.
Set `CC` and `AR` for the desired target; retain the toolchain's normal link mode.
Neighboring implementation/interface records and compiled artifacts are reusable.

`prepare-normal.py` accepts the round package, preceding progression normal
package and an output directory. It selects cleanup in the existing launch,
64-frame gameplay and close workload. Inspect `selected_round_cleanup`,
`selected_round_frees` and outer-call records for actual coverage; selection alone
does not establish execution. Wine comparisons always use headless Wayland.

The practical compiler profile accepts this C. The optional restricted proof
frontend reports the typed-helper macro and the `free` service syntax as
unsupported; concrete execution remains available and grants no strong
qualification. These finite comparisons assume well-formed list graphs and
terminating callbacks.

Every semantic integration discrepancy must have a retained component, boundary
or small connected reproduction. Missing inputs are coverage gaps; inability to
express or execute the relevant state or interaction locally is a tooling gap.
A successful game rerun alone cannot close either gap. The complete application
must not be the only way to diagnose supported behavior.
