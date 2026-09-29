# Standalone Hello: source, runtime bindings and two architectures

The grouped reset/decode adapter now uses the same
[portable assembly declaration](../../../docs/component-module-workflow.md) as
jq. Its C stays unchanged; entry mappings, source files and context lifetime are
retained explicitly in the source project.

This is the practical whole-program follow-up to the
[source export](../hello-source/README.md). It produces a conventional C source
project with application entry, option handling and runtime bindings. The program
does not load the original executable, a fixture driver, Python or the extractor.
The original PE and test-only observer are required only for comparisons.

The 2026-09-22 checkpoint at `build/hello-standalone-2026-09-22/` passes 73 program
cases on x86-64 and AArch64 under QEMU. `workflow-v1` also detects a deliberately
wrong intermediate UTF-16 value whose printed output is unchanged, replays the
retained faulty binary after source repair, and checks the repaired program.
Four integrated Nix shards pass 42 tests and six repository/SDK gates. Current
readers revalidate the unaffected Hello/jq/DX-Ball component receipts separately;
that is not fresh execution of those older jq/DX-Ball workloads.
This is a practically validated **Windows-1252, redirected-stream configuration**,
not complete locale coverage, general Win32 portability or strong qualification.

The subsequent UTF-8 entry checkpoint at `build/hello-utf8-entry-2026-09-22/`
passes the expanded 82-case matrix on both architectures, and preserves the
raw-byte entry's 82-case regression. The portable entry adapter receives original
UTF-8 arguments directly and computes the narrow bytes itself. Its best-fit
mapping is checked against the Windows API under Wine for all 1,112,063 non-NUL
Unicode scalars and 1,024 generated strings. `workflow-v1` edits that mapping,
catches a resulting option-parsing discrepancy, replays and repairs it.
Five integrated Nix shards pass 44 tests and six repository/SDK gates. The
checkpoint audit revalidates the source/binary/profile bindings, actual UTF-8
arguments supplied to the source process, raw observations and unchanged neighbor
receipts. It also verifies both relocated binaries equal the compared builds.

`build/hello-allocation-failure-2026-09-22/` adds 17 controlled-allocation cases on
both architectures, the ordinary 82-case regression, and a wrong-exit defect/
replay/repair workflow. Ten cases reach an injected failure; seven distinguish
bypass, disabled or unreached requests. Six integrated Nix shards pass 46 tests
and six gates. The source project and diagnostic overlay build outside the
checkout to identical binaries. See the allocation section below for the exact
service intervention; physical memory exhaustion is not claimed.

The subsequent `build/hello-component-roundtrip-2026-09-22/workflow-v2/` exercises
public component start/check/reuse and `candidate export --update` through the
assembled program. A changed scan implementation produces a different binary and
passes 82 cases on both architectures; 17 allocation scenarios also pass on x86-64.
The operator's application/backend files and notes survive updates. A bad component
is diagnosed, refused by the updater, replayed after draft repair and rechecked.
The full workflow takes 90.349s; export updates take approximately 1.1s. Six Nix
shards pass 50 tests and six gates. The same export/update/build facility transfers
to jq's source library, without claiming a new complete jq execution.

## Prepare and build

Use the pinned executable and current matching connected/string/stream comparisons from
the [normal-entry](../hello-program/README.md) and
[string-boundary](../hello-string-conversion/README.md) and
[stream-boundary](../hello-stream-close/README.md) recipes. Those recipes explain
fresh setup; historical developer output directories are not required. Retain the
matching upstream source archive once, without rebuilding the pilot:

```sh
nix build --impure --out-link build/hello-upstream --expr '
  let f = builtins.getFlake ("git+file://" + builtins.getEnv "PWD");
  in (import f.inputs.nixpkgs { system = "x86_64-linux"; }).hello.src'
```

Inside `nix develop .#lifting`:

```sh
spaghetti-extractor candidate export gnu-hello \
  --comparison build/hello-program-workflow/program-repaired \
  --comparison build/hello-string-workflow/local-repaired \
  --comparison build/hello-stream-check \
  --output build/hello-source
python tests/fixtures/hello-standalone/prepare.py \
  --source-export build/hello-source \
  --upstream-tar build/hello-upstream --output build/hello-standalone-project
python tests/fixtures/hello-standalone/build.py \
  build/hello-standalone-project build/hello-standalone-build --entry utf8
build/hello-standalone-build/hello --greeting='café'
```

The exported library can travel separately from its comparison workspaces. With
`--source-export`, preparation uses the public source-handoff reader and existing
V3 packages; it needs no original binary, comparison directory, Wine or native
compiler. It copies only the inventoried source inputs, omitting old build products
and operator scratch files. The original comparison identities, boundaries and
service declarations remain in the library's provenance.

To prepare outside the checkout, stage the library, pinned source archive,
`hello-standalone/` recipe/C files, sibling `portable-runtime/` directory and
`native/allocation-fault.h`, using the installed toolkit. The latter header is
needed only to prepare the existing optional diagnostic overlay. Once assembled,
the project builds with ordinary C tools as described below. The older repeated
`--comparison` arguments remain a shortcut that exports the selection first;
choose one input mode.

The staged handoff at `build/hello-export-assembly-2026-09-23/` assembles in 0.105s
with comparison readers, checkout/original-oracle reads and preparation subprocesses
blocked. It builds the current ten-component selection on x86-64 and AArch64 and
matches the original's default program behavior and live conversion observations
on both. Only that case is rerun for this handoff; the broader matrices above keep
their original build bindings.

Preparation adds ordinary application/adaptor C, the shared `portable-runtime/windows-1252`
backend and the unchanged GNU option scanner from the SHA-pinned Hello archive.
Application control and text are source-assisted using that upstream source and
the actual original entry/call sites. This is not a claim that arbitrary stripped
application control has been automatically recovered. GNU source licensing is
retained, including `COPYING.hello`; the combined application is GPL-3.0-or-later.
The option-scanner files retain their LGPL notices.

The resulting directory can be copied elsewhere and built with ordinary
`make CC=cc AR=ar`. Its Makefile needs a C11 compiler, archiver and usual Unix build
tools. It builds `hello` for target narrow bytes and `hello-utf8` for ordinary
UTF-8 arguments. The evidence recipe defaults to the former and selects the
latter with `--entry utf8`; its retained executable is named `hello` in either
case, with the entry profile bound in `build.json`. Redirected output remains target
Windows-1252 bytes/CRLF. POSIX terminals select the experimental UTF-8 console text
backend described below; its supported scope differs from redirected byte output.
The generated project includes a standalone README and the shared backend
contract so its inputs, services, ownership and assumptions travel with it.
Nix provisions the tools in this experiment; no separate OS image without
a Nix store was tested. Switching toolchains or flags requires `make clean`.

`build.py` is the evidence recipe: it validates the exported source, retains a
complete editable source snapshot, builds that snapshot cleanly, and binds the
compiler, inputs, logs and binary. Application/backend edits are recorded as
source changes. Changing exported component C requires public comparison and
re-export; old component receipts do not apply to edited bodies. Clean evidence
builds deliberately do not claim incremental compiler-cache reuse.

## Console comparison

The same source project can now render ordinary Windows-1252 text as UTF-8 on a
POSIX terminal. It preserves the observed console tab, wrap and wide-call behavior
under the shared backend's column-zero, fixed-width, single-writer assumptions.
No component or proof model changes are involved. This remains a partial console
backend: the all-byte control sweep still differs from the original.

Provision the independent screen observer once:

```sh
nix build .#test-fixture-terminal-screen --out-link build/terminal-screen
spaghetti-headless-wayland python tests/fixtures/hello-standalone/terminal.py \
  build/hello-standalone-build build/hello-standalone-oracle build/hello-terminal \
  build/terminal-screen/bin/terminal-screen
```

Use a `--entry utf8` ordinary build. `--case accent` selects one observation;
omitting it runs the complete matrix, including the known mismatch, and therefore
currently returns exit 2. It never silently changes that discrepancy to a pass.
To replay a failed implementation, run the same command against its retained
build directory after repairing the editable project, then rebuild and compare.

The launcher executes the untouched and instrumented originals on an actual
private Win32 console. The portable program runs on a fresh PTY; libvterm observes
its bytes. The observer must not change either program's output or exit. Compared
data includes complete Unicode cell rows, cursor, redirected bytes, exit and
application allocation/conversion observations. Cases include shared or separately
redirected stdout/stderr, 80/100-column displays, scrolling, control/line boundaries
and original output code pages 437/1252/65001. Narrow arguments remain ACP1252.
Screen pixels, fonts, colors and bell delivery are unobserved. Combining/wide
cells outside this observer's capability reject instead of discarding information.

Evidence is retained under `build/hello-console-2026-09-22/`; the current goal
ledger records the final runs and remaining mismatch. Other C0/C1 controls and DEL,
unknown initial cursor positions, resizing, concurrent writers, arbitrary terminal
APIs and console failure paths remain open. This does not replace the separate
redirected-output and allocation-failure regressions or qualify a general console.

## Compare, diagnose and replay

Every Wine application, boot and server runs in headless Wayland:

```sh
python tests/fixtures/hello-standalone/prepare_oracle.py \
  build/hello-original-input/bin/hello.exe build/hello-standalone-oracle
spaghetti-headless-wayland python tests/fixtures/hello-standalone/walkthrough.py \
  build/hello-standalone-project build/hello-standalone-oracle \
  build/hello-standalone-workflow --entry utf8 --defect arguments
```

For a single built artifact, use `run.py BUILD ORACLE OUTPUT`, optionally with
`--case non-ascii`, inside the same wrapper. The walkthrough changes one backend
table entry, compares, repairs the draft, replays the retained wrong artifact and
rebuilds. Faulty source and binaries remain available; no digest editing is needed.
`--defect arguments` changes full-width hyphen conversion, breaking option parsing
and exposing the wrong main-entry bytes, output, exit and application activity.
The default `--defect conversion` retains the earlier UTF-16 defect whose text is
unchanged; both variants support `--entry utf8`.
Replay uses a fresh private runtime directory/prefix and the same greeting and
faulty binary; it does not reproduce an identical OS snapshot or argv[0] pathname.
The linked component sources/contracts/comparison receipts are unchanged. Program
integration reruns because the backend changed. Earlier component-local recipes
separately demonstrate zero compiler/model/solver work for unaffected neighbors.

Each case runs an untouched original, an observation-only original, an observed
portable binary and an unobserved portable binary. Observation must leave raw
stdout, stderr and exit status unchanged on both sides. Comparisons also include
actual main-entry argument bytes, application allocation sizes/counts/releases,
conversion calls/result/cursor, four state bytes, errno, the first 16 UTF-16 words
and a hash covering the complete converted buffer including NUL. This is not a
complete heap or syscall trace. The observer restores original entry bytes around
actual calls; it supplies no replacement application behavior.

The cases cover ordinary greetings, short groups, option abbreviations and error
precedence, `POSIXLY_CORRECT`, help/version, empty/control/accented/unrepresentable
text, a byte sweep, 32 deterministically generated inputs and output failures.
Closed-pipe cases include both sides of the 4096-target-byte buffer boundary and
CRLF expansion. The separate native integration test checks all 256 decoder byte
values against MSVCRT, including results, words, errno and conversion state.
The additional cases cover best-fit letters/options, combining marks, Unicode
boundaries, supplementary characters and diagnostic paths. The Unicode adapter
test also uses sanitizers for malformed/truncated input, unchanged failure frames,
capacity boundaries, exact in-place conversion, vector permutation and disposal.
All original and portable raw outputs remain retained; none are normalized.

## Edit a component and update the assembled program

Open `lifted/README.md`, then the component guide linked there, for the boundary,
source locations, shared objects, services, assumptions and recorded examples.
These generated snapshots travel with the source project and refresh on export.

Edit C in either the local comparison workspace or the standalone source project.
The original comparison package retains the native oracle and adapters; the source
project retains the application/backend code. To edit the exported C directly,
change `lifted/components/string-conversion/sources/source/string.c`, then import
it as an unverified local draft and check it:

```sh
spaghetti-extractor component start gnu-hello string-conversion \
  --comparison-package build/hello-string-packages/string-conversion \
  --reuse-source build/hello-standalone-project/lifted \
  --output build/hello-string-edit
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello string-conversion \
  --comparison-package build/hello-string-edit --output build/hello-string-edited-check
spaghetti-extractor candidate export gnu-hello \
  --comparison build/hello-string-edited-check \
  --output build/hello-standalone-project/lifted --update-components
python tests/fixtures/hello-standalone/build.py \
  build/hello-standalone-project build/hello-edited-program --entry utf8
spaghetti-headless-wayland python tests/fixtures/hello-standalone/run.py \
  build/hello-edited-program build/hello-standalone-oracle build/hello-edited-run --case default
```

The existing [fresh boundary recipe](../hello-string-conversion/README.md) supplies
the comparison workspace and original-side adapters. An exported source library
alone does not contain the original oracle. Repeated checks within one desktop can
use `--reuse-comparison`; cross-desktop environment changes retain their existing
invalidation behavior.
Omit `--reuse-source` to start from the comparison package's C and edit in that
workspace instead. Source-project import checks the selected boundary and non-C
inputs; header, contract and source-layout changes require authoring/refinement.
It leaves the project's previous provenance intact until the checked update.

For a multi-file refactor, use the existing
[`revise_comparison_package(..., source_files=...)` authoring API](../../../docs/component-workflow.md#establish-your-own-boundary).
Supply the complete new C/header set, including `string-objects.h`, then start and
check the resulting package. The original oracle, adapters, cases and interface
are retained. Helper translation units remain part of string-conversion; they do
not need new component definitions. Adding a helper header currently requires
the export's explicit header review described below.

`--update-components` needs only the edited component's comparison. The other
components stay in the library with their own provenance; their comparison
directories are not needed. The existing `--update` mode still takes the complete
selection. Both modes require unchanged declarations, service/representation
requirements and shared/header inputs unless explicitly reviewed. The update accepts the new
matching C, preserves operator files and retains the old library in a printed
sibling backup. It refuses unassured conflicting local edits, changed boundaries
and known mismatches. The application, backend and top-level Makefile are outside
the replaced library and remain intact. Changed components' named build outputs
and the archive are invalidated; unchanged components retain ordinary make outputs
under the same toolchain/flags. Partial updates track per-unit build inputs, also
preserving neighbors across a local source-file split. Program validation remains required. The evidence builder excludes
the declared superseded-library backups from its active source snapshot.

The complete exercised sequence is available as:

```sh
spaghetti-headless-wayland python tests/fixtures/hello-standalone/component-workflow.py \
  build/hello-standalone-project \
  build/hello-string-packages/string-conversion build/hello-program-workflow/neighbor-reused \
  build/hello-standalone-oracle build/hello-component-workflow --edit-export
```

It rewrites the string operation's scanning loop in ordinary C, checks it locally,
reuses the unchanged allocation neighbor with zero compiler/link/execution/model/
solver work, updates the library and runs the standalone program. A bad first output
word is detected locally and cannot overwrite the assembled selection. The draft
is repaired before replaying the retained mismatch. Repaired local evidence reuses
with zero work, the public export updates again, and program execution passes.
The application/backend edits and operator notes survive both updates. Program
builds are clean and make no compiler-cache reuse claim. These are finite behavioral
checks under unchanged declared boundaries, not strong compatibility qualification.
The default walkthrough checks one local case containing 192 sequences and the
normal greeting. Add `--all-cases` when the wider twelve-local/eighty-two-program
matrix is relevant; it is not required for every compatible C edit.
`--edit-export` exercises editing directly in the source project and importing
each draft; omit it to exercise editing in the comparison workspace. The installed
source-project trial at `build/component-source-roundtrip-2026-09-23/` passes in
48.846s, including defect replay, repair and normal program execution.

## Input and runtime contract

Wine's Unix launcher under `LC_ALL=C` can alter UTF-8 before Windows startup. The
earlier `café` -> `cafC)` observation was an **input transport** effect; the prior
attribution to later Hello output conversion was incorrect. Separately, MSVCRT's
`setlocale(LC_ALL, "")` selects the Windows user locale, not Unix `LC_ALL`. The
observed environment uses English/Windows-1252.

The new test launcher starts under `C.UTF-8` and uses Windows argument conversion
to record narrow bytes before launching the original. It checks those bytes
against actual original main entry. The `target` profile receives identical raw
byte arguments, including Windows best-fit/replacement results. The `utf8` profile
instead receives the original arguments encoded as UTF-8; its C adapter must
produce those main-entry bytes without a Windows service or oracle-provided
mapping. The same observation compares its actual narrow inputs. Neither path
uses Hello output to define input transport or normalizes observed output.

The two entries share the same application and component bodies. Their `main`
signatures do not make their input contracts interchangeable. The UTF-8 adapter
owns a single allocation for the mutable vector and strings and registers cleanup
before application handlers, preserving argv references through shutdown and
observation. That platform-entry allocation, like native CRT argument preparation,
is outside the application's checked-allocation counters. See the
[shared backend boundary](../portable-runtime/README.md) for exact preconditions,
failure behavior and scope. Invalid UTF-8 is a rejected host input, not an original
Windows-behavior equivalence claim.

The shared backend defines 16-bit conversion, four-byte state, CRLF and the
observed redirected-stream buffering/error behavior. It keeps target bytes before
CRLF expansion and maps the pinned runtime's broken-pipe behavior explicitly.
The application supplies live allocation/conversion services through existing
generated interfaces. The free adapter maps an opaque 32-bit allocation token to
the actual host pointer; it never truncates a 64-bit pointer. Shared state/layout
knowledge lives in `services.h` and the existing component headers.

Scope is single-threaded command-line execution, initial Windows-1252 conversion
state, successful or explicitly injected failed application allocations and strings below the original signed
allocation frontier. Other code pages/localized catalogs, native Unicode terminal
output, interactive-console behavior, physical allocation exhaustion, arbitrary
signals/callbacks/concurrency and additional host operating systems remain open.
Host startup replaces PE CRT/TLS internals; this tests observable program effects,
not an equality of those internal startup implementations. Existing local fatal,
alias and lifecycle tests retain their separate scopes.

## Allocation failure through normal entry

The ordinary source build contains no fault injector. An explicit diagnostic
build uses an ordinary C adapter and GNU linker overlay:

```sh
python tests/fixtures/hello-standalone/build.py \
  build/hello-standalone-project build/hello-allocation-fault-build \
  --entry utf8 --allocation-fault
spaghetti-headless-wayland python tests/fixtures/hello-standalone/run.py \
  build/hello-allocation-fault-build build/hello-standalone-oracle \
  build/hello-allocation-fault-run
spaghetti-headless-wayland python tests/fixtures/hello-standalone/walkthrough.py \
  build/hello-standalone-project build/hello-standalone-oracle \
  build/hello-allocation-fault-workflow --entry utf8 --defect allocation-exit
```

The build manifest selects the 17-case allocation matrix automatically. It covers
ordinary/empty/traditional/Unicode/long greetings, failed redirected streams,
help/version/invalid arguments that bypass allocation, disabled faults and an
unreached second-allocation request. Every case records the requested ordinal,
actual attempts, failures and size. An unreached fault is never failure coverage.

The native test DLL intercepts the resolved `malloc` import only for the pinned
`_rpl_malloc` call returning to RVA `0x663b`. It returns NULL/ENOMEM at the selected
ordinal. Original allocation checks, fatal diagnostics, atexit handlers and CRT
termination execute normally. The portable test object selects the corresponding
application allocation using the existing adapter's immediate count/size update
before `malloc`. It excludes entry/observation/formatting allocations. Its
`--wrap=malloc` and `--wrap=main` flags are confined to the optional diagnostic
overlay; changing the adapter requires reviewing that selector.

Each fault case compares fault-only and fault-plus-observer originals, then
observed and unobserved portable executions under the same fault. Disabled-fault
controls also compare against the untouched PE. The original observer records
entry to the actual fatal body and its call-time errno; it restores the body
before executing it. It supplies no simulated diagnostic or exit. Immediate fault
reports survive application `_Exit` shutdown. The comparison checks allocation
effects, entry bytes, fatal entries/errno, output and actual process status.

`--defect allocation-exit` changes only the application runtime's fatal exit to
success. Its diagnostic text and memory observations remain identical, but the
comparison catches the wrong process outcome, replays the retained bad binary
after source repair, and validates the rebuilt program. Component bodies,
contracts and comparison receipts remain reusable. Program integration reruns;
the clean build recipe makes no compiler-cache reuse claim. The same explicit
diagnostic configuration supports `--cc`/`--ar` for the AArch64 run below.

This is deterministic lower-service failure, not physical memory exhaustion.
Failure of platform argument preparation, the observation machinery or arbitrary
CRT allocations is outside this application boundary. No checker, artifact or
compiler infrastructure extension supplies the failure behavior.

## AArch64 execution

The retained run used the pinned nixpkgs AArch64 native compiler, executed through
the host's already-enabled QEMU binfmt registration. Obtain that compiler once:

```sh
nix build --impure --out-link build/hello-aarch64-cc --expr '
  let f = builtins.getFlake ("git+file://" + builtins.getEnv "PWD");
  in (import f.inputs.nixpkgs { system = "aarch64-linux"; }).stdenv.cc'
python tests/fixtures/hello-standalone/build.py \
  build/hello-standalone-project build/hello-aarch64-build --entry utf8 \
  --cc "$(realpath build/hello-aarch64-cc)/bin/cc" \
  --ar "$(realpath build/hello-aarch64-cc)/bin/ar"
spaghetti-headless-wayland python tests/fixtures/hello-standalone/run.py \
  build/hello-aarch64-build build/hello-standalone-oracle build/hello-aarch64-run
```

This requires working AArch64 execution on the host; the recipe does not configure
the system. It verifies the ELF architecture and records the actual interpreter
and binfmt registration. The retained evidence is real **emulated execution**,
not a cross-compilation-only check or a physical AArch64 hardware test.

No new proof rule, checker, production artifact format or full pilot rebuild was
needed. Proven properties, runtime assumptions and finite tested behavior remain
separate. The diagnostic project/build/run manifests grant no strong qualification.
