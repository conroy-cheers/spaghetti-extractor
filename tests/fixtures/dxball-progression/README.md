# DX-Ball gameplay progression

[progression.c](progression.c) lifts eight native entries in 109 lines of C:
refresh/draw score and lives, count remaining cells, select the next board, lose
a life, request game over, restart a round and complete a pending transition.
Authoring uses executable instructions and data without the original game source.
[BOUNDARY.md](BOUNDARY.md) records state, callback effects, aliases and ordering.

The component borrows the existing paddle, pickup, motion, gameplay, brick,
palette, scene and graphics objects. Only four newly exposed native words need
a new state view. The existing pickup `next_life` field is the score cache here;
its declaration is retained so neighboring components remain unchanged. Seventeen
services cover rendering, sound, waiting, board loading, palette operations,
ball creation and cleanup. Complete controlled state, palette and board bytes,
live ball records and ordered service arguments/results are observed.

Prepare and compare without starting the game:

```sh
python tests/fixtures/dxball-progression/prepare.py \
  /path/to/DXBall.exe /tmp/dx-paddle-check/inputs /tmp/dx-progress
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-progression \
  --comparison-package /tmp/dx-progress/gameplay-progression --output /tmp/dx-progress-check
```

The 33 cases exercise score caching/overflow, unsigned decimal text, signed life
comparisons, counter wrapping, callback-driven rendering, every board-cell byte,
level limits, life loss, current-ball selection, staged-palette grayscale,
cleanup ordering and restart. Services deliberately change shared state across
calls, including choosing a different current ball before restart marks it
attached. These are concrete terminating scenarios, not universal proofs.

Connect the actual gameplay frame:

```sh
python tests/fixtures/dxball-progression/prepare-frame.py \
  /tmp/dx-progress/gameplay-progression /tmp/dx-frame-check/inputs /tmp/dx-progress-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-progression \
  --comparison-package /tmp/dx-progress-frame/package --output /tmp/dx-progress-frame-check
```

Five cases run up to four real frames each, covering life-loss/restart,
level-change/restart, game over, final-level completion and pausing. Frames stop
when the score-scene transition is requested. Movement is controlled and can
request the actual life-loss routine; creation, cleanup, loading and remaining
helpers are explicit observed services. No game UI or full startup is needed.

For focused diagnosis, use `component check ... --case restart-callbacks` with
the complete package retained. A separate deliberate mutant that attaches the
last ball rather than the current ball is caught by this local case, although
the normal-game workload does not exercise that distinction. Its retained
diagnostic identifies the exact changed ball field and supplies a replay command.

Apply to a copy of the preceding powerup source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-progress-check --accept-boundary-change gameplay-progression \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-progression/assemble.py {project} /tmp/dx-progress-check /tmp/dx-progress-frame-check' \
  --check-command 'make -j2' --check-command 'python check-progression.py' \
  --check-command 'python check-progress-frame.py'
```

Both scripts also accept `--runner /path/to/qemu-aarch64`. Supply that architecture's
compiler and archiver through `CC`/`AR`; the retained toolchain uses its normal
dynamic libc, so adding `-static` is inappropriate. Neighboring implementations,
interfaces and existing source consumers can be reused.

`prepare-normal.py` accepts the progression package, the preceding powerup normal
package and an output directory. It selects the C in the existing launch/gameplay/
close workload using real services. Inspect `selected_progression` and outer
operation records for actual coverage; installing all entries does not mean the
workload reaches them. All Wine comparisons run under headless Wayland.

Every semantic integration discrepancy must be reduced to a retained component,
boundary or small connected consumer. Missing cases are coverage gaps; inability
to express or execute the relevant state/interaction locally is a tooling gap.
A successful game rerun alone cannot close either gap. The standalone consumers
remain usable when automating an entire target application is impractical.
