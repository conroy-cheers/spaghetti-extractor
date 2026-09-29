# DX-Ball powerup actions

[power.c](power.c) lifts seven native operations into 145 lines of C: split balls,
expand explosive cells, soften bricks, detonate, super balls, drop the board and
release attached balls. Authoring uses executable instructions/data without the
original game source. [BOUNDARY.md](BOUNDARY.md) records shared state, temporary
lists, allocation, callback effects and graphics rectangle aliasing.

The component reuses the existing motion, gameplay, board and graphics types. Its
temporary ball/cell lists are actual native state, with the same existing record
types as the live lists. No neighboring implementation or interface changes.
Thirteen services cover allocation/disposal, termination, drawing, hits, rebound
and sound. Native and source comparisons observe complete controlled live records,
roots, board bytes and ordered service arguments/results.

Prepare and check without starting the game:

```sh
python tests/fixtures/dxball-powerups/prepare.py \
  /path/to/DXBall.exe /tmp/dx-shots-check/inputs /tmp/dx-powerups
spaghetti-headless-wayland spaghetti-extractor component check dxball powerup-actions \
  --comparison-package /tmp/dx-powerups/powerup-actions --output /tmp/dx-powerups-check
```

Thirty scenarios cover all seven actions, temporary list consumption, preexisting
records, speed/counter wrapping, allocation/free callbacks, board scan order,
successive callback-driven cell changes, hit outcomes, falling cells, aliased
mutable blit rectangles and attached-ball release. Returning termination backends
exercise allocation-failure continuations with valid current records; they do not
claim actual process-exit coverage.

Connect the actual pickup and frame consumers:

```sh
python tests/fixtures/dxball-powerups/prepare-frame.py \
  /tmp/dx-powerups/powerup-actions /tmp/dx-pickups-check/inputs \
  /tmp/dx-frame-check/inputs /tmp/dx-power-frame
spaghetti-headless-wayland spaghetti-extractor component check dxball powerup-actions \
  --comparison-package /tmp/dx-power-frame/package --output /tmp/dx-power-frame-check
```

Seven cases execute four actual frames each, collecting a pickup that triggers
splitting, super balls, expansion, softening, detonation or release. Pausing
preserves the pickup. Movement, overlap, graphics and remaining helpers are
controlled and observed. This checks the real collection/control path and shared
objects without a window or complete application startup.

Apply to a copy of the preceding explosion source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-powerups-check --accept-boundary-change powerup-actions \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-powerups/assemble.py {project} /tmp/dx-powerups-check /tmp/dx-power-frame-check' \
  --check-command 'make -j2' --check-command 'python check-powerups.py' \
  --check-command 'python check-power-frame.py'
```

The exported consumers use ordinary C and Python without Wine or the game. Check
scripts accept `--runner /path/to/qemu-aarch64` for cross builds. Existing component
records and eligible compiled objects remain reusable.

Select the actions in the normal-game comparison:

```sh
python tests/fixtures/dxball-powerups/prepare-normal.py \
  /tmp/dx-powerups/powerup-actions /tmp/dx-explosions-normal-check/inputs /tmp/dx-power-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball powerup-actions \
  --comparison-package /tmp/dx-power-normal/package \
  --output /tmp/dx-power-normal-check --comparison-timeout 90
```

This retains the prior workload and twenty-eight components. The observer uses
the existing ball/event identity maps for live and temporary lists. An allocation
observer registers transient split/expansion allocations on both sides so later
identities do not depend on which C call graph inspected temporary records.
Fresh links are never followed; reachable payloads and links cross boundaries.

The retained 64-frame workload reaches none of these seven entries. Its match
checks continued normal execution with the selection installed, not powerup
behavior or that allocation observer's active branches. Local and connected
consumers provide the behavioral evidence. Every semantic integration finding
must remain reproducible independently; inability to express it is a tooling gap.
