# DX-Ball board-editor continuation — 2026-09-28

The initial attempt stopped because the normal-program runner rejected a real
save as damage to an immutable runtime input. That runner limitation is now
resolved; it was independent of the component interfaces, new editor C and Wine
diagnostic output. The seven editor entries are now integrated into both the
portable source project and real normal-entry execution.

## Editor integration

The public `candidate apply` path adds the existing native-checked editor through
`assemble.py`. Seventeen components implement 63 native entries. All 201 retained
source-consumer cases pass on x86-64 and AArch64, including the sixteen editor
cases with full board bytes, hit regions, interaction traces, pixels and object
lifetimes. All sixteen neighboring implementation/interface/contract identities
and all 43 old compiled objects remain unchanged; only three objects are added.
The incremental apply and its build/check commands take 13.069s. The clean ARM
build takes 53.719s and its QEMU checks 67.885s; all twelve consumers are AArch64 ELF.

`prepare-normal.py` explicitly rebinds the controlled menu/board requirements to
the existing live network. It transports the same editor, board, menu and scene
backing around synchronous services and reentry. The original CRT, hit-region,
cursor and board-rendering bodies remain services. The board observer is factored
for reuse by the editor observer; its existing observations are retained.
The first preparation rejected an incomplete explicit replacement list before
execution. Naming all selected existing dependencies through the public API
resolved that recipe error; no checker or artifact changes were needed.

The real ten-frame clear/save/close workload passes on its first execution with
the editor C selected. Plain, original and source all exit zero. Application
streams, saved files, state and executable service checks agree. Seven outer
editor records retain current/saved boards, all 25 hit regions, input/scene state
and primary/back surface and palette hashes. The selected C entry counts are
`[1,2,4,2,0,0,0]` for enter/redraw/update/key/palette/status/leave. Palette/status
execute as ordinary internal C calls, so their wrapper counts are zero; leave
is not reached by this close workload. Local native cases exercise all seven
entries independently. Board load/save/select/store each execute once, with 46
tile mappings. Saved `Default.bds` is 20,000 bytes, with the first board cleared
and the other 49 unchanged; all three hashes are
`e70b7e341db0871c3a9ada6b62a64e170ed42039fc9643bc526db1559079f22a`.

The live comparison records 0.784s preparation, 1.004s component compilation
(21 units compiled, 14 reused), 0.064s link, 42.586s Wine startup wall time and
31.189s across three executions. Its small output-capture launcher takes 0.214s
to compile. Model/solver work is zero; no large pilot rebuild is involved. Manual
adapter preparation is separate from these measured command phases.

The editor C needs no behavioral correction after integration feedback. No new
semantic discrepancy required reduction in this step. The local cases already
exercise save failures, partial reads, unusual flags and a rendering callback
that changes both input and board index. A future application-only discrepancy
must become a local component, boundary or connected-consumer regression; a
passing application rerun alone does not close it. Finite checks cannot guarantee
that every possible behavior is already covered.

Evidence root: `build/dxball-editor-integration-2026-09-28/`.

- `program/`, `program.apply-vd14scg6/`, `apply-time.json`: source assembly and all
  thirteen build/check commands.
- `prior-export.json`, `prior-files.json`, `reuse.json`: unchanged neighboring
  identities and compiled objects.
- `arm-program/`, `arm-validation.json`, `arm-build.log`, `arm-check.log`: clean
  second-architecture build and 201 matching cases.
- `normal-prepared-2/`, `normal-check/`: reviewed live boundary, matching native
  receipt, application and host streams, exact saved files and editor observations.
- `normal-prepared/`, `normal-prepare.log`: rejected initial selection recipe.
- `validation.json`, `tree-audit.json`: receipt/source identity checks and dirty
  tree preservation. `nix-checks.log` records repository validation.

## Runtime-file follow-up

The existing driver's `process.mutable_files` declares writable working files.
An existing runtime input supplies the initial bytes, or an output starts absent.
Each side has a private copy that persists between cases. Per-case file snapshots
and presence/content observations participate in the normal comparison, its
untouched-original control, retained-result reuse and experimental candidate runs.
Immutable program inputs stay checked. Working-file validation failures retain a result with
explicit failed/not-run sides and cases.

The public save recipe now declares `Default.bds` mutable. Its actual ten-frame
clear/save/close workload matches: all three sides exit zero, save the same 20,000
bytes, clear the first board and preserve the remaining 49. The selected existing
board component executes load/save/select/store once each and tile mapping 46
times. Application streams, observer state and resource checks also match.
All 33 component objects are reused, with no model/solver work or pilot rebuild.
The small capture launcher is compiled and the existing observer network relinked.

The first run after the fix retained matching saved files but timed out while the
source process was closing, without a complete capture report. Its result remains
incomplete. An identical replay passes without changing C or increasing deadlines;
this does not establish that Wine/controller shutdown is free of intermittent
failures. The earlier cache-reuse request without an explicit case selection was
rejected before execution because this workload differs from the baseline suite.

Evidence root: `build/mutable-program-files-2026-09-28/`.

- `save-prepared/`: public workload with the mutable-file declaration.
- `save-check-2/`: retained incomplete first execution and matching saved bytes.
- `save-replay/`: matching full replay, file snapshots and bound observations.
- `native-final.log`, `unit.log`: passing native program/experimental integration and regression
  checks, including file-only defects, suite persistence, creation/deletion,
  snapshot reuse and retained failures.
- `focused-final.log`: a regression rerun interrupted by Wine prefix startup;
  its nine unit checks pass, and the complete native check passes in `native-final.log`.
- `nix-checks-final.log`, `validation.json`, `tree-audit.json`: final repository
  checks, evidence binding and preservation of unrelated changes.

This follow-up selects the previously verified sixteen-component network, not
the seven new editor entry bodies. It does not apply or export the editor C or
extend its AArch64 evidence. The supported file boundary uses the current flat
working-directory layout; see [the public workflow](component-workflow.md).

## Completed local lifting

[The editor component](../tests/fixtures/dxball-board-editor/README.md) authors
seven actual entries in ordinary C: enter, redraw, update, key dispatch, palette
rendering, status rendering and leave. The existing board component provides
load/save, select/store and tile mapping. Existing scene/font/graphics objects
retain their identities and contents; the new editor state owns the selected
tile, board index and explicit hit-region backing.

Sixteen native cases match, with all seven entries and all five board operations
executed. They observe complete current/saved board bytes, hit regions, file
state, text spans, service order, pixel backing and object lifetimes. Cases cover
paint/erase and Ctrl repetition, palette selection, signed cursor clamps, strict
board edges, noncanonical flags, board index bounds, low-byte keys, file failures,
partial reads and real board data. A rendering callback changes mouse buttons,
Ctrl state and board index, exercising rereads and transport across a synchronous
call boundary. The two button branches can both execute within one update.

The first native run found an incomplete adapter premise: the inherited test
bank contained five font glyphs but lacked the tile slots used by the palette.
The untouched original faulted when it dereferenced an absent sprite. Adding
actual backing for those slots corrected the fixture. The final check also retains
menu damage-rectangle calls; it compiled one adapter and reused 22 objects, with
all sixteen cases passing. The authored editor C needed no behavioral correction.
No checker, compiler or artifact machinery
was changed. Native board renderer, hit-region and cursor helpers remain explicit
target services; the controlled local backend is not a claim that those additional
bodies have been lifted.

The final local check takes 0.366s compilation, 0.064s link, 12.716s Wine
startup wall time and 7.529s for 32 native executions with full byte observations.
Manual analysis/authoring is separate. Model/solver work is zero, and no large
pilot rebuild was required. Authoring consulted executable instructions/data
and retained assets, without original game source or third-party implementations.

## Initial integration blocker

The public preparation recipe changes only the existing normal-game workload,
retaining its sixteen-component board/graphics network. The new editor C is not
selected. The external controller uses the existing hardware frame breakpoint,
ordinary window messages and read-only process memory. At ten total frames it has
entered scene 2, cleared the current board, saved with S and closed. It never writes
application code/data or files itself.

The untouched original exits zero, and its Windows output capture reports success.
Its private `Default.bds` remains 20,000 bytes: the first board is cleared, exactly
168 bytes change (offsets 105..294), and the other 49 boards remain byte-identical.
The comparison CLI then exits 2 with:

```text
comparison runtime input changed: Default.bds
```

The normal runner hashes all files listed in `runtime_files`, then calls
`check_runtime_inputs` before and after each process. Its program configuration
accepts only exit codes and an optional DOS drive. It has no way to classify a
seeded data file as mutable application state or observe the resulting file
effects. It also rejects new top-level working files. Local C adapters can model
file writes, but this normal-entry path cannot currently validate the application's
actual save behavior. An exceptional exit bypasses the comparison receipt writer;
the partial process artifacts and runtime files remain available for diagnosis.

The needed change at that checkpoint was an execution boundary separating
immutable program prerequisites from seeded mutable application data. Keep pristine replay inputs,
give each side private mutable copies with defined suite persistence, and compare
declared file outcomes, including contents and creation/deletion. Bind that state
to the retained result and retain an explicit failed/not-run diagnostic when a
case cannot complete. The existing comparison plan, runner and observations are
the appropriate extension points. This concerns execution/file-state handling,
not additional proof rules or editor-specific C behavior.

## Scope and evidence

Further lifting stopped at that checkpoint under the requested stop condition.
The runner follow-up removes that restriction, and the editor integration above
extends the verified assembly to seventeen components, 63 native entries and
201 source-consumer cases on x86-64/AArch64. A complete portable game, remaining
target helpers/gameplay, startup and platform backends remain open.

Evidence root: `build/dxball-board-editor-2026-09-28/`.

- `prepared-3/`, `check-3/`: final public editor preparation and sixteen matching
  native cases, including menu damage-rectangle observations.
- `check/`: the first original-side fault from the missing palette sprite backing.
- `save-prepared/`: public real-editor workload against the previous normal network.
- `save-check.log`: the rejected legitimate runtime data mutation.
- `save-check/cases/0000-plain.capture.json`: successful original exit/capture.
- `save-check/runtime-plain/tmp/controller.log`: actual frame/input route.
- `save-check/runtime-plain/Default.bds`: the application's saved file; pristine
  replay input remains in `save-check/inputs/runtime/Default.bds`.
- `save-blocker.json`: file hashes, byte differences, process status and explicit
  absence of instrumented executions and a comparison receipt.
- `nix-checks.log`: repository metadata, production Python lint and format-registry
  checks passed. Whitespace validation also passed.
- `validation.json`, `tree-audit.json`: evidence revalidation, source/input identity
  checks and preservation of unrelated worktree changes.

Every Wine execution uses headless Wayland. These finite practical checks do not
claim strong qualification or complete game equivalence.
