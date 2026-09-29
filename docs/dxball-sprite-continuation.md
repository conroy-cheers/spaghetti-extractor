# DX-Ball sprite continuation — 2026-09-27

The binary-only lift now connects sprite-bank loading, font metrics, drawing and
cleanup. The new work used existing public interfaces, ordinary C, service
bindings, comparison, export and `candidate apply`; it required no checker,
compiler or proof-engine change. Manual setup remained substantial, but did not
prevent progress. The attempt initially stopped at a normal-program observation
problem. The follow-up below resolves it through shared Windows output capture.

## Delivered connected subsystem

The [reproducible fixture](../tests/fixtures/dxball-sprite-font/README.md) adds:

| Component | Native entry RVAs | Responsibility |
| --- | --- | --- |
| `font-metrics` | `bd80`, `c660`, `c760` | Select font bank, find character, measure text |
| `font-render` | `c5a0`, `c6b0`, `c720` | Draw glyph, line and centered line |
| `sprite-loader` | `c080` | Read sprite banks, allocate objects, initialize and populate surfaces |

Together with the three preceding cleanup units, these are six components and
ten native entries. Existing cleanup C, contracts and object layout are reused.
Metadata accessors name newly understood fields in the existing sprite storage;
there is no new global heap model or synthetic per-loop production API.

The font checks cover signed lengths/counts, embedded NULs, wrapping coordinates
and advances, missing/zero-width glyphs, and state mutation during drawing. The
asset checks use shipped `Sysfont.sbk`, `Sfont.sbk` and `Thefont.sbk` bytes, and
observe allocations, file progress, service ordering, sprite contents, surface
pixels and padding, drawing arguments, failure leaks and subsequent cleanup.
The original PE32 instructions remain the oracle; selected bodies are trapped
on the source side. Original source was not consulted. Prior knowledge of the
cleanup/graphics layout and previous adapter code was reused explicitly.

All **40 font comparisons and six connected asset comparisons match**. The
exported source consumers also match all **20 font and six asset cases on both
x86-64 and AArch64 under QEMU**. These are practical, scoped tests, not universal
equivalence, real rasterization qualification or a complete portable game.

## A real editing/debugging iteration

The initial loader translation incorrectly published `count + 1`. The native
loader fills slots 1 through count, but publishes count; the font search's strict
less-than bound consequently skips the last loaded slot. The public comparison
reported `$.loaded.banks[0][255]`: original `94`, source `95`. Inspection showed
this was the only observed difference in the first real-asset case.

The operator corrected only `loader.c` through `component start`'s source-file
edit. The next comparison passed all six cases, compiling **one** translation
unit and reusing **twelve**. The five neighbors' unit inputs were unchanged.
The subsequent `candidate apply` added the loader to the existing source project
and passed its build and standalone workload checks before publication.

Automatic font preparation took 0.62 seconds. The first metrics/render checks
took 21.4/12.9 seconds, including Wine startup. Actual compilation was
0.45/0.49 seconds and linking about 0.06 seconds each. No pilot, model or solver
ran. These timings exclude the much larger manual boundary/adapter authoring
effort; improving that setup remains useful but was not the stopping condition.

## Normal-program observation and resolution

The untouched game starts in headless Wayland. A further public normal-entry
experiment then replaced metrics and cleanup using **actual game heap objects,
the original allocator and real DirectDraw services**. That transport was ordinary
C adapter work; it did not require new tool internals. The original entry and
TLS were retained, and an external controller waited for the game window,
posted input, and requested normal closure.

In the final probe, plain/original/source all exit `0`. Source execution enters
font select/find/measure **7/458/4** times and cleanup select/dispose/clear
**18/2795/2** times. The instrumented original and replacement have identical
retained observations for the first 32 metric calls. This bounded observation
does not establish matching frames, audio, all later calls or an entire playthrough.

The initial public result was **`incomplete / invalid-observation`**. The untouched
original emits one additional identical Mesa/RADV warning on stderr. There are
no other raw-stream differences after the existing service telemetry is removed.
The old collector compared entire host stderr when checking instrumentation
transparency and reported “instrumentation changes original program behavior.”
That earlier receipt retains its original incomplete classification.

The follow-up uses a small Windows launcher backed by the existing
`pe32-process-observer.h`. Before entry/TLS execute, the child receives separate
Win32 stdout/stderr pipes; Wine/Mesa/ALSA stderr remains with the host runner.
Both channels, the launcher and its completion report are retained. Application
bytes still compare exactly under the existing telemetry rules. No diagnostic
text filter, comparison exception or weaker proof standard was introduced.
Experimental candidate runs reuse this same capture path.

The public recheck **passes**: all three executions exit zero and the first 32
metric-call observations match, with the selected-entry counts above unchanged.
The plain host log contains three RADV warnings while original/source each contain
two; the host logs remain available independently. Launcher compilation took
0.21 seconds. Only this bounded comparison was rebuilt; no pilot was rebuilt.
Regression checks preserve application warnings even when their text matches
host warnings, reject real application differences, and exercise experimental
candidate execution through the same capture. A reproducible GUI input/readiness
protocol and real frame observations remain further integration work.

## Evidence and limits

Evidence root: `build/dxball-sprite-continuation-2026-09-27/`.

- `prepared-1/`, `check-1/results.json`: two new font units and 40 native comparisons.
- `assets-check-1/`: retained genuine count mismatch; `loader-edited/` and
  `assets-check-2/`: local correction, matching six cases and compilation reuse.
- `program.apply-gtq2y3je/`: successful source-project update; `program/` is the
  resulting standalone connected consumer. `arm-program/` and `arm-assets/`
  retain the corresponding AArch64 executions.
- `normal-probe-1/`: untouched startup/close. The GDI capture is black and does
  not demonstrate frame correctness.
- `normal-check-3/`: first live replacement execution; initial controller timing
  made the untouched control fail. `normal-check-4/` fixes readiness and retains
  the concrete host-stderr observation failure and matching component reports.
- `result.json`, `validation.json`, `tree-audit.json`: summarized scope, validation
  and preservation of pre-existing work.

Follow-up evidence: `build/wine-output-separation-2026-09-27/normal-check/`
contains the matching public comparison and `cases/*.host.stderr` diagnostic
logs. Its sibling `native.log` and `unit-2.log` retain the focused regression runs.

All Wine applications ran inside headless Wayland. The source project is a
subsystem consumer with controlled portable graphics services. Actual normal-game
execution still uses native services and most original code; neither mode is a
full portable DX-Ball. Strong qualification and authoritative activation receipts
are unchanged and were not claimed by these comparisons.
