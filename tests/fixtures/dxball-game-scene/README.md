# DX-Ball gameplay scene

[game.c](game.c) lifts scene entry, redraw and key handling in 80 lines of C.
Authoring used the pinned executable's instructions, key tables and asset names,
without the original game source. [BOUNDARY.md](BOUNDARY.md) records shared state,
callback ordering, rectangle aliasing and the comparison domain.

The component borrows existing progression and damage objects, with their shared
scene, graphics, sprite and gameplay state. Its only newly exposed scalar is the
stereo direction used by native sound panning. Entry loads assets and 25 sound
slots, resets game state, loads a board and restarts the round. Redraw preserves
mutable rectangle aliases; keys implement pause/resume, guarded cheats, music
selection and stereo reversal. Platform effects and neighboring operations are
explicit services.

Prepare and compare without starting the game:

```sh
python tests/fixtures/dxball-game-scene/prepare.py \
  /path/to/DXBall.exe /tmp/dx-round-check/inputs /tmp/dx-game
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-scene \
  --comparison-package /tmp/dx-game/gameplay-scene --output /tmp/dx-game-check
```

The 24 cases exercise entry and redraw in both presentation modes, surface aliases,
callback changes to surfaces/banks/transition decisions, rectangle mutations,
every input byte with cheats enabled and disabled, arbitrary-key resume,
nonboolean pause values, current-bank widths, unsigned doubling, all music
choices including out-of-range service results, and finite stereo-direction
values. Observations retain state, live ball payloads/links, board/palette bytes,
sprite metadata and ordered service arguments. They are finite concrete cases.

Connect the already lifted progression implementation:

```sh
python tests/fixtures/dxball-game-scene/prepare-connected.py \
  /tmp/dx-game/gameplay-scene /tmp/dx-progress-check/inputs /tmp/dx-game-connected
spaghetti-headless-wayland spaghetti-extractor component check dxball gameplay-scene \
  --comparison-package /tmp/dx-game-connected/package --output /tmp/dx-game-connected-check
```

Three connected cases run real entry/restart/score drawing, pause/resume through
recursive scene redraw, and cheat changes followed by round restart. Scene entry
calls progression restart, which dispatches scene redraw, which calls progression
score drawing. Both components use the same objects; remaining platform, board
loading and ball-allocation services are controlled and observed. No full startup
or UI automation is needed.

Apply to a copy of the preceding round-cleanup source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-game-check --accept-boundary-change gameplay-scene \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-game-scene/assemble.py {project} /tmp/dx-game-check /tmp/dx-game-connected-check' \
  --check-command 'make -j2' --check-command 'python check-gameplay-scene.py' \
  --check-command 'python check-game-connected.py'
```

Both source consumers run without Wine and accept `--runner /path/to/qemu-aarch64`.
Set `CC` and `AR` for that architecture, retaining the toolchain's normal link mode.
The new consumers keep their helper headers in `common/game-scene/` to preserve
existing consumer headers and compiled artifacts.

`prepare-normal.py` takes the gameplay-scene package, preceding round-cleanup
normal package and an output directory. It selects all three operations in the
retained launch/gameplay/close workload. Inspect `selected_game_scene` and outer
records for actual coverage; selection alone does not establish execution. All
Wine applications run under headless Wayland.

The practical compiler profile accepts the C and checks its immutable static
storage. The optional restricted proof frontend reports its static tables/text
as unsupported; no formal check or strong qualification is claimed. Every semantic
integration discrepancy requires a retained local or small connected reproduction.
Missing cases are coverage gaps; inability to represent, execute or observe the
behavior without the whole application is a tooling gap.
