# DX-Ball damage tracking and presentation

[damage.c](damage.c) lifts thirteen native entries through one shared queue and
scene boundary: reset, tracked cursor/sprite drawing, marking, erasing,
restoration, background/destination selection, presentation, flushing, sorting
and rectangle overlap. [BOUNDARY.md](BOUNDARY.md) describes the actual aliases,
lifetime requirements, callbacks and machine arithmetic. Inputs are executable
instructions/data and existing operator-authored interfaces, without original
game source or new checker/compiler machinery.

Use the retained lifting environment and existing scene package:

```sh
python tests/fixtures/dxball-damage/prepare.py \
  /path/to/DXBall.exe /tmp/dx-scene/title-scene /tmp/dx-damage
spaghetti-headless-wayland spaghetti-extractor component check dxball damage-tracking \
  --comparison-package /tmp/dx-damage/damage-tracking --output /tmp/dx-damage-check
```

The nineteen local scenarios exercise the actual original entries without the
game UI. They compare every history/pending rectangle and sorting key, final
pixels, object contents, guards and ordered interactions. Cases include queue
capacity, clipping, exact flag words, surface aliasing, mutable callbacks,
busy/lost/error presentation, wrapping clocks, generated rectangle geometry and
reset before surfaces are bound. The source side traps all selected native bodies.

The edit workflow exposes a meaningful local discrepancy:

```sh
spaghetti-extractor component start dxball damage-tracking \
  --comparison-result /tmp/dx-damage-check --output /tmp/dx-damage-edit
```

In `source/damage.c`, replace `pending(state, state->history[i][state->page])`
with `pending(state, *rectangle)`. The `restore-callback` case reports
`$.damage.states[2].pending[5][0]`: original 31 versus edited C 51. The callback
switched the active page; remembering the previously selected rectangle loses
that change. Restore the original expression to repair it. Only the edited C
unit needs recompilation, with eighteen neighboring units reused. Rectangle
observations are indexed fields, so the diagnostic does not dump a whole buffer.

Apply to a copy of the existing board-rendering source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --comparison /tmp/dx-damage-check --accept-boundary-change damage-tracking \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-damage/assemble.py {project} /tmp/dx-damage-check' \
  --check-command 'make -j2' --check-command 'python check-damage.py'
```

The assembly preserves all prior consumers. Its new `damage` consumer needs
ordinary C and standard Python, without Wine, the original binary, game assets
or the lifting tools. Use the lifting environment's full Python path for the
assembly command if another interpreter lacks its preparation dependencies.
The check scripts accept `--runner /path/to/qemu-aarch64` for cross execution.

Select the same C in the normal editor workload:

```sh
python tests/fixtures/dxball-damage/prepare-normal.py \
  /tmp/dx-damage/damage-tracking /tmp/dx-render-normal/package /tmp/dx-damage-normal
spaghetti-headless-wayland spaghetti-extractor component check dxball damage-tracking \
  --comparison-package /tmp/dx-damage-normal/package \
  --output /tmp/dx-damage-normal-check --comparison-timeout 55
```

This explicitly refines the controlled consumer to actual live objects and
platform services. It retains the preceding editor/board/render observations,
queue hashes, surface identities and selected pixel hashes. Absolute clock
readings remain diagnostics; controlled clock behavior is compared locally.
An early live observer dereferenced an unbound surface at reset. The local
`unbound-reset` case now exercises this startup state through the same
[observation helper](damage-observation.h), without a window or editor session.

Any future semantic discrepancy from whole-game execution must be reduced to
a component, boundary or small connected regression. If the documented boundary
cannot express the state or interaction, treat that as a tooling gap. Finite
comparisons do not guarantee universal correctness. See the
[continuation record](../../../docs/dxball-damage-continuation.md) for retained
results and remaining game/platform work.
