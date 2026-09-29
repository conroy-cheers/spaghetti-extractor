# Authored components inside native Hello quoting callers

This recipe reuses the three C components from the
[allocation/quoting workflow](../hello-allocation-growth/README.md) inside actual
PE32 Hello caller routines. The original quoting engine, lower allocation,
errno and cleanup routines execute under Wine. No new component implementation,
proof rule or solver model is introduced.

This is a native **routine** comparison with explicit initialization assumptions.
It does not execute untouched Hello process startup, qualify native replacement,
or produce an all-portable Hello executable. The full public recipe is
`walkthrough.py`; exact commands, inputs, outputs and phase costs are retained in
its output directory. Every Wine process runs inside a headless Wayland desktop.

The 2026-09-22 checkpoint at
`build/hello-native-quoting-2026-09-22/workflow-v2/` passes all fourteen commands,
nine comparisons and the 21-case experimental assembly in 64.397s. Two native
integration tests, the headless runner check and six repository/SDK gates pass;
the existing 42-case jq assembly also passes under the updated runner. The prior
attempt remains retained with its diagnosed Weston kiosk-shell crash.

The fresh-package follow-up at
`build/first-time-components-2026-09-22/hello-native-workflow-v2/` repeats the full
recipe in 61.707s using `--component-packages`. Its input network is prepared from
only the three original slices and repository C/declarations, with no completed
comparison as a prerequisite. It retains the same 21-case native scope.

The subsequent [stateful conversion recipe](../hello-multibyte/README.md) selects
the complete quoting engine and conversion family alongside the allocation/cache
units. The native package derives this transitive selection from the engine's
dependency graph. It runs 63 cases: the original 21 sequences in native C, native
Japanese and explicitly controlled UTF-8 contexts. The eight-unit public
edit/replay/reuse and experimental run pass; startup/TLS remain outside the scope.
Extra transitive local checks use `--component-comparison ID=PATH`; those checks
must bind the selected implementations. No parallel supplier-selection list is
required. The earlier sections describe the original three-unit checkpoint.

## Original and replacement boundaries

`prepare_image.py` requires the original Hello 2.12.3 PE32 executable with SHA-256
`71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`.
It sets the DLL characteristic, clears the entry point/checksum and removes the
TLS directory in a test-only copy. It checks that every changed byte belongs to
those header fields and that every on-disk section is unchanged. The Windows
loader then resolves imports and relocations normally. The driver supplies CRT
initialization and the C locale; original startup and TLS callbacks are omitted.
`image-preparation.json` binds the exact original, routine image, edits and owned
body bytes. This preparation is fixture machinery, not a production PE converter.

| Selected C unit | Original owned ranges, RVA | Boundary |
|---|---|---|
| `quote-slots` | `[4eb3, 5078)`, cold fragment `[14645, 1464a)` | Mutable cache table/count, initial table/buffer, borrowed options and argument bytes; returns the cached output pointer |
| `allocation-grow` | `[63ac, 6462)` | Nullable allocation, mutable count cell, additional count, maximum and element width; calls actual `xrealloc`/`xalloc_die` |
| `preserve-errno-free` | `[1b34, 1ba0)` | Nullable buffer and the actual CRT errno cell; calls actual `free` |

The native adapter uses the existing C units and growth/free bridges unchanged.
It checks PE32 record sizes and offsets and synchronizes the original cache
globals with the explicit source context at the boundary. Its pointers designate
the live native objects; it neither recreates heap contents from addresses nor
serializes the graph into equal values. Calls are synchronous and nonreentrant.

The candidate side replaces every byte of each selected main body with traps,
apart from the entry jump to authored C. The quote cold fragment is also trapped.
The exit check verifies those bytes and jumps remain intact and that all three
source units actually ran. The fixture uses the common PE32 entry/import helpers;
its internal addresses are trusted only for the pinned image. It establishes no
general interception or coverage rule for other executables.

The actual callers are `quotearg_n_style` at `53e5`, `quotearg_n_style_mem` at
`5416`, and `quotearg_n_custom_mem` at `55e7`. The actual cleanup routine at `52f2`
calls the selected free replacement too. Lower dependencies include the quoting
engine at `36ea`, `xrealloc` at `6257`, `xcharalloc` at `6255`, and the loaded CRT
imports. These native dependencies remain required by this configuration.

## Cases and observations

Twenty-one cases cover ten styles through string and explicit-length callers,
plus custom delimiters. Each case makes six calls using slots 0, 3, 15, 19, 3, 0,
then cleans up, reenters the actual caller and cleans up again. Inputs include
spaces, quotes, slashes, newlines/tabs, embedded NUL bytes and a 600-byte argument.
The sequence exercises table growth, cached-buffer replacement and reuse after
cleanup: 147 native consumer calls per comparison side.

Compared observations include returned text, errno, initialized slot capacities
and contents, normalized buffer identities, cleanup/reentry state, allocator
call order, requested sizes and residual live allocations. The observer forwards
the actual resolved `malloc`, `realloc` and `free` imports. A reallocation retains
its logical identity whether the CRT moves it or not. Unknown/dead allocation
identities reject. Physical allocator movement, uninitialized bytes and allocation
inside other DLLs are not compared. The fixture has finite observation capacities.

Native cases do not cover allocator exhaustion, invalid slot abort, original
startup/TLS, asynchronous callbacks, concurrency or arbitrary reentrancy. The
independent growth suite covers controlled failure/overflow cases; that evidence
does not become native exhaustion coverage. Existing program defects must remain
visible rather than being silently repaired by the adapters.

## Public edit, compare, replay and integration

For original startup and TLS execution, the separate
[normal-program workflow](../hello-program/README.md) reuses these component
objects and adapters with `--program-observer`. Its command-line cases execute
allocation, free, conversion and reset; they do not reach every installed quoting
operation. Keep this routine suite for the broader native consumer coverage.

The [fresh-input handoff](../hello-handoff/README.md) prepares the current connected
selection using `nix develop .#lifting`, the original executable and retained
transfer plan. It requires no historical comparison package. This recipe's
`prepare.py` also accepts omission of its environment-package argument to use
those shell tools; explicit retained environment inputs remain supported below.

Prepare fresh allocation/quoting packages from the original slices using the
[network recipe](../hello-allocation-growth/README.md). A completed earlier
comparison or workflow is no longer required. Also retain a valid
PE32 comparison package containing the compiler, Wine tools and compiler runtime
DLLs; only that environment is reused, not its target-specific runtime. The
original Hello executable is a separate required input. Within the project
Python/compiler environment, run:

```sh
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=.:src spaghetti-headless-wayland \
  python tests/fixtures/hello-native-quoting/walkthrough.py \
  build/hello-components /path/to/retained-pe32-comparison/inputs \
  /path/to/original/hello.exe build/hello-native-workflow --component-packages
```

Run the whole recipe in one desktop so compatible edits retain the same compiler
and execution context. Different contexts can legitimately invalidate reuse.
The earlier completed-workflow input mode remains available by omitting
`--component-packages`; the flag explicitly selects fresh packages.
The recipe uses public `component start/check` and `candidate build/test` commands:

1. Materialize the native package and independently check growth, free and the
   native consumer network.
2. Edit growth compatibly, check it, then rerun the affected native integration.
   Only the changed translation unit recompiles. The free neighbor reuses its
   local result with no compiler, link, execution, model or solver work.
3. Remove the root's embedded-NUL flag, diagnose the native consumer mismatch,
   restore the draft and replay the retained faulty inputs. The repaired network
   reuses the earlier matching evidence.
4. Select all three units under an explicit experimental policy and execute the
   selected network. The native integration and the host-local supplier checks
   keep their respective environments and observation scopes explicit.

Formal checking is not requested. Experimental receipts bind the source, input,
adapter, runtime, policy and binary evidence; strong qualification and native
dispatch/link readers do not accept them as authority. The recipe still uses the
reviewed manual boundaries and C for this network. Fresh preparation removes a
historical package dependency; it is not a usability study of an unfamiliar
target or whole-Hello completion.

The optional `--cleanup-package` argument extends this same walkthrough with the
[complete cache cleanup component](../hello-quoting-cleanup/README.md). Its local
comparison excludes the release supplier body. Native integration selects all
four components, traps the original cleanup body, edits cleanup independently,
reuses the growth neighbor, replays a reset-capacity defect and executes a
four-unit experimental assembly. This mode records 25 commands and 19 comparisons;
the original three-unit recipe remains available without the argument.

The optional `--reallocate-package` argument additionally selects the
[complete realloc component](../hello-reallocation/README.md) beneath native
`xrealloc`. It adds a real zero-size caller probe and declared controlled failure/
high-bit probes, checks an independent realloc edit, reuses free, and replays a
wrong zero-normalization value locally and through the native caller. With both
optional packages the 2026-09-22 recipe passes 36 commands, 29 comparisons and the
five-unit experimental assembly in 141.578s. Original-body trap checks and counters
confirm all selected C runs. These probes do not establish native allocator
exhaustion or the higher wrappers' fatal termination paths.

The optional `--checked-allocation-package` argument selects the
[shared-tail allocation family](../hello-checked-allocation/README.md): eight C
operations, two short ABI aliases and one owned return/failure tail. With all three
optional packages the 2026-09-22 recipe passes 47 commands, 39 comparisons and the
six-component experimental assembly in 198.331s. It exercises every family entry
on success and controlled nonlocal failure, edits the family independently, and
reuses lower realloc. The shared tail is trapped; short entry branches are checked
against selected primary entries. `xalloc_die` delivery is a controlled service in
this mode, so actual fatal process termination remains a separate obligation.

The optional `--quote-engine-package` argument selects the
[complete quoting engine](../hello-quote-engine/README.md). It adds all eleven
quoting styles through ordinary C with explicit live locale/conversion services.
With all four optional packages, `build/hello-quote-engine-2026-09-22/workflow-v1/`
passes 59 public commands and 50 comparisons in 344.145s. The engine's local
matrix covers 18,480 transformations per side; the native suite still covers
21 real-consumer sequences. A compatible edit recompiles one local and one native
integration unit; the controlled local quoting caller reuses with zero work.
Wrong NUL elision fails both checks, both failures replay after repair, and both
repaired results reuse. The seven-component experimental assembly also passes.
The engine's full 6,089-byte body and cold region are removed from source-side
native execution. Locale/conversion services and original startup remain explicit
remaining dependencies; finite comparisons do not grant strong qualification.

## Actual fatal diagnostics and process termination

`prepare.py --terminal-failures` selects a separate nine-case suite using the same
authored allocation family and native image. It requires
`--checked-allocation-package`; the cleanup/realloc options remain available.
The three caller entries are allocation (`622d`), resize (`6257`) and the short
array-resize alias (`62b6`). Each runs with the actual `exit_failure` cell set to
1, 37 and 0. Nonzero status goes through native `error` and CRT exit; zero reaches
the actual abort import after printing the diagnostic. Raw allocation failure is
still injected. This covers terminal handling, not physical allocator exhaustion.

Each case runs in a child of the comparison driver. The `xalloc_die` observer
records current errno, allocator requests, logical live blocks and the old block's
eight initialized bytes, restores the original fatal entry, then calls it. No
child jump handler intercepts termination. Original and replacement agree on
`memory exhausted`, the requested exit statuses, and abort status 3 in the retained
Wine environment. The native error routine flushes the buffered state observation.
Normal quoting and cleanup remain covered by the separate 21-case suite.

The installed [PE32 process observer](../../../src/spaghetti_extractor/resources/native/pe32-process-observer.h),
selected with `native_adapter_headers("pe32-process-observer.h")`, captures
the full DWORD exit code and binary stdout/stderr. Its 16 KiB per-stream limit,
10-second case timeout and launch/pipe errors reject incomplete observations.
The child and descendants belong to a job killed on close. Only the three standard
handles are inherited. This is test machinery, not an operating-system sandbox;
cross-stream ordering, original Hello startup/TLS, custom diagnostic callbacks,
signals and asynchronous delivery remain outside this scope. Windows error dialogs
are disabled; `exit` and `abort` are not replaced. All processes run under the
owning headless Wayland desktop.

Generated service instrumentation also writes stderr. This fixture reserves its
`SPX_SERVICE`/`SPX_SERVICE_SCOPE` line prefixes, forwards those exact records to the
existing protocol checker, and compares the remaining program bytes. After actual
child termination, the supervisor delivers the observed failure to its own C
handler. The handler transports telemetry; it does not implement the child's
failure path. Missing or malformed protocol remains a failure. Arbitrary target
output containing those reserved prefixes would require a separate trace channel.

After preparation, the focused public edit loop is:

```sh
spaghetti-headless-wayland python tests/fixtures/hello-native-quoting/terminal_walkthrough.py \
  build/terminal-packages/quote-slots build/checked-packages/checked-allocation \
  build/terminal-workflow \
  --component-comparison allocation-grow=build/native-workflow/growth-baseline \
  --component-comparison preserve-errno-free=build/native-workflow/release-baseline \
  --component-comparison quote-cleanup=build/native-workflow/cleanup-baseline \
  --component-comparison allocation-reallocate=build/native-workflow/reallocate-baseline
```

Use the same sanitized compiler environment as the normal recipe. Supply one
local comparison for each selected neighbor; omit cleanup/realloc rows if those
components were not selected. These are reusable input comparisons, not a fixed
historical directory requirement. The recipe starts an editable allocation draft,
compares a compatible change, reuses an unchanged neighbor, deliberately removes
the failure call, replays both local/native discrepancies after repair, and builds
and tests the existing experimental selection. A missing failure call yields
`$.terminal.exit_code`: 37 in the original, 0 in the replacement. No component,
proof rule, solver model, comparison format or production authority is added.

The accepted checkpoint at `build/hello-native-terminal-2026-09-22/` uses
`packages-v4/` and `workflow-v2/`: all 18 public commands and 15 comparisons pass
in 84.409s, including the nine-case experimental run. The unchanged realloc check
takes 0.960s with zero compiler/link/execution/model/solver work. The separate
normal regression passes its complete 47-command recipe and 21-case assembly.
Thirteen Nix tests and six repository/SDK gates pass. The checkpoint audit validates
54 receipts, both assemblies and current fixture/engine bytes. Earlier attempts
retain the diagnostic/trace separation issue; the accepted comparison checks the
forwarded protocol rather than suppressing it. No original pilot rebuild ran.
