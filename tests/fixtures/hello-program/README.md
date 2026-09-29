# Hello through original program startup and selected C

The public `component start/check/status` workflow launches Hello as a program.
Local edits, selected suppliers, discrepancy replay and compiler/evidence reuse
use the same commands and result artifacts as routine comparisons. Its original
entry point, section bytes, relocations and TLS directory are preserved on disk.
One added DLL import loads the component objects compiled by the comparison
workflow. The DLL supplies the existing native C
adapters and installs the selected components before original startup. The base
selection contains eight components; the optional string-conversion workspace is
another independent program entry.
No new proof rule, comparison format or qualified-native admission is involved.
The recipe uses `revise_comparison_package` to retain selected C and neighbors,
replace its reviewed observer headers and declare normal program execution.
`program_entry_packages` adds the optional string entry through the existing
composition resolver. The recipe no longer installs dependency rows or rewrites
generated plans, hashes, composition or headers itself.
The recipe declares the private drive `P` and invokes `P:\hello.exe` on all sides.
This keeps startup pathname observations stable when the workspace or a packaged
experiment moves. Old comparisons without that declaration retain their old
invocation and need a fresh comparison before using it.

Run every command that launches Wine, wineboot or wineserver inside headless
Wayland. The commands below use the project's `nix develop .#lifting` shell.

## Fresh setup and public workflow

Obtain the pinned original and transfer plan using the
[fresh-input recipe](../hello-handoff/README.md), then prepare with the optional
program observer:

```sh
python tests/fixtures/hello-handoff/prepare.py \
  build/hello-original-input/bin/hello.exe \
  build/hello-plan-input/executable-transfer-plan.json \
  build/hello-program-packages --program-observer
python tests/fixtures/hello-program/comparison.py \
  build/hello-program-packages/native/quote-slots \
  tests/fixtures/hello-native-quoting/program-runtime.h \
  build/hello-program-prepared
spaghetti-extractor component start gnu-hello multibyte-conversion \
  --comparison-package build/hello-program-packages/conversion/multibyte-conversion \
  --output build/hello-conversion
spaghetti-extractor component start gnu-hello quote-slots \
  --comparison-package build/hello-program-prepared --output build/hello-program
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello multibyte-conversion \
  --comparison-package build/hello-conversion --output build/hello-conversion-baseline
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello quote-slots \
  --comparison-package build/hello-program \
  --dependency-package multibyte-conversion=build/hello-conversion \
  --output build/hello-program-baseline
```

Preparation needs reviewed input packages, not a passing comparison or pilot
rebuild. Edit `build/hello-conversion/source/multibyte.c`, check it locally, then
run the affected program consumer. A focused workload keeps the edit loop short:

```sh
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello multibyte-conversion \
  --comparison-package build/hello-conversion \
  --reuse-comparison build/hello-conversion-baseline --output build/hello-conversion-edited
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello quote-slots \
  --comparison-package build/hello-program \
  --dependency-package multibyte-conversion=build/hello-conversion \
  --reuse-comparison build/hello-program-baseline --case default \
  --output build/hello-program-edited
```

The CLI reports the first differing output byte or state field and prints a replay
command. Raw stdout/stderr and observer reports are retained under `cases/`.
For changed program streams it also shows the byte offset and escaped output
around that point, so text, CR/LF, NUL and target-encoding differences are visible.
It does not decode or normalize the compared bytes. `status --comparison-result`
shows this diagnostic from retained evidence without running the program again;
state-file links point to the observer reports. JSON output remains the full
comparison result.
Replay uses the saved implementation even after the draft is repaired. Restoring
previously compared C can reuse both local and program evidence without execution;
`--rerun` requests fresh execution while reusing eligible object files. A focused
case is not a fresh result for the entire twelve-case matrix.

The [walkthrough](walkthrough.py) automates that operator sequence, including a
reversed reset loop, a deliberate decoded-character defect, replay after repair,
unaffected-neighbor reuse and source-library export/build:

```sh
spaghetti-headless-wayland python tests/fixtures/hello-program/walkthrough.py \
  build/hello-program-packages/conversion/multibyte-conversion \
  build/hello-program-packages/native/quote-slots \
  build/hello-program-packages/base/allocation-grow \
  tests/fixtures/hello-native-quoting/program-runtime.h build/hello-program-workflow
```

Stage `comparison.py`, `walkthrough.py`, the C observer and reviewed packages in an
operator directory to use the installed toolkit outside this checkout. They have
no `tests.fixtures` imports. The recipe supports the reviewed eight-component
selection and the string-conversion entry below; other selections still require
reviewed adapter work.
It is a prepared-example trial, not independent human usability evidence.

The installed-tool checkpoint at `build/component-normal-program-2026-09-23/`
passes this sequence in 85.276s of public commands. It checks all twelve baseline
workloads and the default workload after edits; repaired program reuse takes
1.108s with zero compiler/link/execution work. Four affected Nix shards pass 38
tests and seven repository/SDK/build gates pass. No pilot rebuild is needed.

## Hand off a runnable experiment

Prepare an explicit experimental policy from the passing program selection.
This example supplies the local conversion check and explicitly relies on the
program cases for the other suppliers:

```sh
spaghetti-extractor candidate policy gnu-hello \
  --comparison build/hello-program-baseline --configuration hello-program \
  --component-comparison multibyte-conversion=build/hello-conversion-baseline \
  --network-only allocation-grow --network-only allocation-reallocate \
  --network-only checked-allocation --network-only preserve-errno-free \
  --network-only quote-buffer --network-only quote-cleanup \
  --output build/hello-review
```

Read `build/hello-review/README.md` and `experimental-policy.json`, then run the
printed `candidate build` command. It produces `build/hello-review-experiment`.
Run that package with:

```sh
spaghetti-headless-wayland spaghetti-extractor candidate test gnu-hello \
  --experimental-package build/hello-review-experiment --output build/hello-experiment-run
```

The [policy](../../../docs/components.md#experimental-component-check-requirements)
must name the full selection and accept its assumptions. By default it requires
matching separate receipts for every component. For a program-level experiment,
explicitly list the required separate checks in `required_component_checks`; the
main program comparison is always required. The preparation command calculates
these bindings without a custom script or hash edits. The CLI names the remaining units
with only selected-network evidence. A supplied stale or mismatching receipt still
rejects. To require independent local comparisons for more units, omit their
`--network-only` options and supply their matching receipts. Program cases do not
exercise every linked quoting operation; the observer reports that limitation.

Build retains the comparison executable, authored DLL and receipts without
compiling or linking. The package can move independently of the supplied
comparison folders; its recorded Nix toolchain/runtime paths must still exist.
Test launches the selected C through actual Hello startup and checks the original
arguments, output, exit status and observer state. The retained original/control
comparison supplies expectations. This mixed program retains native services;
portable source assembly uses `candidate export` and the standalone recipe.

After checking a compatible conversion edit and its affected program workloads,
reuse the previous experiment's policy and other component receipts:

```sh
spaghetti-extractor candidate build gnu-hello \
  --experimental-comparison build/hello-program-edited \
  --reuse-experimental build/hello-review-experiment \
  --component-comparison multibyte-conversion=build/hello-conversion-edited \
  --output build/hello-next-experiment
```

Use a full program comparison for packaging: omit the earlier `--case default`
restriction when producing `hello-program-edited`. The changed conversion receipt
must match the selected C and boundary. Other matching receipts are retained
automatically; units explicitly accepted through program evidence keep that
status. The old experiment stays usable, and the new one contains its own copies.

To resume from that handed-off experiment without the original preparation folders:

```sh
spaghetti-extractor component start gnu-hello multibyte-conversion \
  --experimental-package build/hello-next-experiment --output build/conversion-next
```

Open its generated workspace guide and edit its C. Run the printed check command
inside the headless Wayland desktop. The command also shows how to reopen
`quote-slots` with this conversion workspace selected; no numbered receipt path
lookup is needed. Reopening `quote-slots` directly restores the normal program
workspace. A supplier accepted only through program evidence needs a separately
prepared local comparison before it can be reopened for independent checks.

## Add an independently edited program entry

Prepare the [string-conversion workspace](../hello-string-conversion/README.md),
then include it when preparing the program:

```sh
python tests/fixtures/hello-program/comparison.py \
  build/hello-program-packages/native/quote-slots \
  tests/fixtures/hello-native-quoting/program-runtime.h build/hello-string-program \
  --string-package build/hello-string-packages/string-conversion
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello quote-slots \
  --comparison-package build/hello-string-program \
  --dependency-package string-conversion=build/hello-string-draft \
  --case default --output build/hello-string-program-check
```

The program can enter both string conversion and quoting independently. Its
`program_driver.entries` records those roots without declaring a call between
them. The string adapter reaches the selected multibyte service at its existing
entry. A single DLL and observer compare the program streams, TLS, allocation and
conversion state, including the string operation's implicit state. Actual string
call counts remain visible in the reports. Edits, retained replay, compiler reuse
and source export now use public commands for this selection too; no second DLL
or separate program runner is required. The CLI's `quote-slots` identity names the
package workspace, not sole ownership of normal program entry.

The authoring API also handles entries with transitive suppliers: unchanged
shared selections are retained once, and conflicting selected bodies or contracts
reject without publishing a partial workspace. Choose a consistent selection
before retrying. The original caller's requirements stay frozen. Native ABI,
shared state and program entry interception remain the reviewed C observer's work.

`build/component-program-entry-revision-2026-09-24/` exercises the migrated recipe
with a local string C edit. Both base and additional-entry preparations preserve
the former recipe's consumed inputs exactly. The focused default workload passes
through normal startup, observes the selected string body and both TLS callbacks,
then reuses unchanged evidence with zero compilation/execution and exports source.
This validates the preparation handoff, without rerunning the twelve-case matrix.

## Earlier bundle consumers

The retained bundle recipes remain available for historical string-conversion
replays and standalone-oracle consumers. They are no longer required for the
public component edit loops above. For an existing matching
native comparison:

```sh
python tests/fixtures/hello-program/prepare.py \
  build/hello-program-workflow/native-compatible build/hello-selected-program
spaghetti-headless-wayland python tests/fixtures/hello-program/run.py \
  build/hello-selected-program build/hello-program-observations
```

The preparation recipe imports
`spaghetti_extractor.components.comparison_pe32_program.add_experimental_import`
from the installed toolkit. `prepare.py`, `run.py` and a retained comparison can
also be staged in an operator directory outside the checkout; they require no
Python imports from `tests.fixtures`. The installed-helper handoff recorded in
`build/installed-program-helper-2026-09-23/` exercises that arrangement on the
existing default workload, with checkout reads blocked in Python. Original
boundary and adapter preparation remain separate operator work.

The older program bundle contains the retained comparison and objects, compiler link
command, DLL, original executable, import-extended executable and exact file
bindings. `prepare.py --diagnostic` permits a known mismatch only as a visibly
diagnostic experiment. This recipe does not authorize activation or bypass a
failed local comparison. Ordinary experimental candidate policy and strong
qualification retain their existing admission checks.

## What executes and what is observed

Every case runs the untouched original, the original with the observer, and the
selected C with the observer. Output and exit behavior of the first two must match.
The original and selected sides also compare ordered allocation requests, logical
live allocation identities, residual allocations, both implicit conversion-state
cells and TLS callback counts. Generated service traces are retained and checked
by the existing nesting/outcome reader. They are separate from target stderr;
malformed or incomplete telemetry is an error.

The observer forwards both original TLS callbacks with their actual arguments and
records process-attach execution. It observes and forwards the original CRT
`exit` import. Hello closes stderr during its actual atexit processing, so the
enclosing service observation ends before forwarding that call; the state report
is written at DLL teardown. This does not emulate program termination. Unexpected
exit paths or missing reports reject. General signals, callbacks, reentrancy,
concurrent execution and arbitrary termination protocols are not supported by
this fixture.

The cases cover default/traditional/custom/empty/accented/quoted/long greetings,
help/version, an unknown option, an unexpected operand and a missing greeting
argument. They enter the selected checked allocator, free, 16-bit conversion and
state reset. The complete quoting engine, slot growth/cleanup, reallocation,
32-bit conversion and initial-state query are installed but not reached by these
command-line workloads. Per-operation counts make this visible. The separate
63-case native routine suite remains necessary for those consumers.

Wine resolves the executable pathname before constructing startup arguments.
Distinct `source`/`original` directory names originally caused different startup
allocation sizes. Each side now runs at the same absolute pathname with freshly
staged, verified inputs and its own Wine prefix. All case outputs are retained
outside that working directory; unexpected mutations reject. The path can differ
between separate runs and is retained in the command log. Replay compares the
same faulty component bytes and arguments; it is not an identical OS snapshot.

The current host emits Fontconfig warnings in raw stderr. They remain captured
and compared; they are not filtered into a successful result. The environment is
explicitly `LC_ALL=C`; the later [standalone investigation](../hello-standalone/README.md#input-and-runtime-contract)
established that Wine's launcher changes accented input before original main entry.
This observation must not be attributed solely to Hello's conversion routines.
It is not native UTF-8 locale support or a portable locale backend. Allocation
observation still excludes physical movement, uninitialized
bytes and internal allocations in other DLLs.

The reusable import helper accepts unsigned PE32 programs with existing imports
and spare section-header space, rejects duplicate/missing imports and preserves
original section/TLS/relocation bytes. It is a bounded experimental loader utility,
not a replacement for the qualified native composer. The Hello C adapter remains
pinned to the reviewed binary, addresses, calling conventions and shared layouts.

Normal program execution is a practical integration step. The subsequent
[previously unprepared string boundary](../hello-string-conversion/README.md) now
passes through the retained bundle facilities. The
[standalone source handoff](../hello-standalone/README.md) also runs on x86 and
AArch64 within its explicit Windows-1252 redirected-output profile. Wider platform
and runtime coverage remains open; this mixed program comparison does not itself
produce a complete portable application.
