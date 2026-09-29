# Source-blind DX-Ball cleanup trial

Three previously unprepared operations were authored from the pinned PE32's
instructions: select a bank, dispose one sprite, and clear all sprite banks.
No original game source or third-party reimplementation was consulted. The
operator already knew the existing graphics fixtures and bank layout. See
[BOUNDARY.md](BOUNDARY.md) for exact ranges, assumptions, state and service scope,
and the [trial review](../../../docs/source-blind-lifting-trial.md) for findings.

The comparison executes original x86 instructions, then installs the selected C
behind native entry adapters and traps those original bodies. Local checks include
calls from the unchanged original cleanup loop. The connected check replaces all
three operations. Release/free services and initial objects are controlled; this
does not run normal game startup or native DirectDraw/allocator internals.

In `nix develop .#lifting`, with a retained pinned `DXBall.exe`:

```sh
python tests/fixtures/dxball-cleanup-blind/prepare.py \
  /path/to/DXBall.exe /tmp/cleanup-packages
spaghetti-headless-wayland python tests/fixtures/dxball-cleanup-blind/walkthrough.py \
  /tmp/cleanup-packages /tmp/cleanup-work
```

Preparation uses public APIs and `component start --interface-intent`. It also
retains machine-derived C, semantic inputs and timings, but the executable
oracle is the actual PE32. `select-authoring`, `dispose-authoring` and
`clear-authoring` contain editable interfaces, ordinary C, shared headers,
assumptions and generated editor support. The preparation recipe supplies the
explicit native setup through `prepare_comparison_package`.

The walkthrough opens comparison workspaces, checks 6 selector, 28 disposal and
23 connected cases, refactors disposal, reuses selector evidence, reruns the
consumer, injects a stale-pointer defect, replays it after repairing the editable
file, and reuses the repaired result. Generated cases vary initial memory and
counts; deliberate cases cover empty slots, null surfaces, shared surfaces,
dangling slot aliases, last slot 254, dense banks and synchronous service mutation.
All Wine processes stay in the headless Wayland desktop. Keeping one shell and
launcher preserves eligible evidence reuse; a new environment can invalidate it.

Inspect an established boundary without rebuilding:

```sh
spaghetti-extractor component status dxball cleanup-dispose \
  --comparison-package /tmp/cleanup-work/clear-edited/inputs
```

Build a standalone source consumer from the baseline export, then update it with
the independently edited disposal component using the normal assembly action:

```sh
python tests/fixtures/dxball-cleanup-blind/assemble.py \
  /tmp/cleanup-work/program /tmp/cleanup-work/clear-baseline
make -C /tmp/cleanup-work/program
python /tmp/cleanup-work/program/check.py
trial_recipe="$PWD/tests/fixtures/dxball-cleanup-blind/assemble.py"
spaghetti-extractor candidate apply dxball \
  --project /tmp/cleanup-work/program \
  --comparison /tmp/cleanup-work/clear-edited --component cleanup-dispose \
  --assembly-command "python $trial_recipe {project} /tmp/cleanup-work/clear-edited" \
  --check-command 'make -j2' --check-command 'python check.py'
```

The delivered project builds with a C compiler and standard `make`. Its checker
uses Python's standard library and retained native observations, without the
original executable or installed toolkit. For another architecture, copy the
source tree without `build/`, `cleanup`, `liblifted.a` or retained backup trees;
set `CC`/`AR`, build, then use `check.py --runner /path/to/qemu-aarch64` as needed.
The recorded trial executed all 23 standalone cases on x86-64 and AArch64 under
QEMU. This consumer still supplies controlled release/free services.

Preparation failures and an initial script assertion typo are retained in
`build/source-blind-component-trial-2026-09-27/`. The corrected full walkthrough
completed in `workflow-2/`; the actual source-project update and portable builds
use `workflow-1/`. Both contain the same corrected component C and contracts.
No target-specific checker, proof engine or compiler extension was needed. A
missing installed observation header required one generic package-data fix.
