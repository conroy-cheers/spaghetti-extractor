# DX-Ball DirectDraw lifecycle comparison

For successful initialization and an actual resource consumer, use the newer
[connected graphics walkthrough](../dxball-graphics-network/README.md). Its manual
state map corrects the primary/backbuffer slots and includes the real reset/bind
continuation omitted by the older authored draft. The eight early-failure cases
here remain useful regressions but do not validate those later paths.

This fixture applies the shared component comparison workflow to the real
DirectDraw initialization tail starting at RVA `0xcd5c`. Its original-side oracle
is the existing machine-derived C slice, with exact input files bound by the
comparison package. The authored side is `targets/dxball/source/directdraw-init.c`
using its existing V5 interface and generated headers. No new production API or
per-target Python checker is introduced.

The eight cases cover negative and positive nonzero DirectDraw-create results,
and successful creation followed by negative and positive nonzero cooperative
level results, with two sets of window identities. A nonnegative create result
writes the returned resource even if the nonzero status takes the failure branch.
This distinction is observable and must not be simplified to `status == 0` when
transporting the output resource.

Each side starts in a separate process. The fixture compares return values, all
eight declared state words, hide/message/destroy ordering and arguments, window
lifetime and the surviving DirectDraw resource. The sequence deliberately does
not invent a DirectDraw release absent from the original failure paths. Service
calls validate resource identities, generations, tags and current lifetime.
Unknown machine reads, writes or calls fail instead of returning default values.

The original continuation frame has saved ESI and EBX at entry ESP offsets 0 and
4, with the return address at `0x218`. The fixture checks both saved registers and
final ESP (`entry + 0x21c`). ESI supplies the controlled ShowWindow target. Memory
projections come from the existing binding intent. Sentinel state words make
unintended writes visible. The entry frame and service implementations are fixture
assumptions; reachability from the preceding window-creation code is not proved.
Only the two early failure branches are supported. Later initialization,
reentrant window callbacks, actual Win32 services and GUI behavior remain outside
this experiment. This is retained-C comparison, not native-original equivalence
or strong qualification.

## Public workflow

From the repository development shell (`nix develop`), build the reusable package
once. This fixture runs host executables; it does not launch Wine or Win32 services.

```sh
PACKAGE=$(nix build --no-link --print-out-paths \
  ./targets#legacyPackages.x86_64-linux.targets.dxball.target.directdraw-lifecycle-comparison-package)
```

Start a writable draft and compare it with the retained-C oracle:

```sh
spaghetti-extractor component start dxball directdraw-init \
  --comparison-package "$PACKAGE" --output /tmp/dxball-draft
spaghetti-extractor component check dxball directdraw-init \
  --comparison-package /tmp/dxball-draft --output /tmp/dxball-baseline
```

Edit `/tmp/dxball-draft/source/directdraw-init.c`. Changing
`DXBALL_MESSAGE_COOPERATIVE_LEVEL_FAILURE` from 2 to 1 is a meaningful bug: the
four cooperative-level cases report the wrong error message. Check again using
`--reuse-comparison /tmp/dxball-baseline` and a new output directory. The command
reports the first divergent service observation and a replay command. Replay
case `2` directly from the retained failed result's `inputs` directory, repair
the source and recheck. Repeating an unchanged repaired check reuses evidence
with zero compiler, execution, model, solver and link work.

Replacing hide-window with destroy-window exercises a different failure: the
controlled lifecycle rejects destroying the window before the required hidden
state, and the result is incomplete with a fixture diagnostic. This failure does
not count as a passing behavioral comparison.

The retained experiment is under
`build/practical-lifting-2026-09-15/dxball-lifecycle-v1/`: `commands.json`,
`transcript.log`, and `audit.json` bind baseline, bug, replay, repair, reuse and
invalid-lifetime results. The initial experiment uses retained preparations;
the public SDK package regenerates that same oracle through the existing exact-C
slice preparation when its inputs change. Neither path requires a qualified
portable pilot or native-link rebuild for a routine source edit.
