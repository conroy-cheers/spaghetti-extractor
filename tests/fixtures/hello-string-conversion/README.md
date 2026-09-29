# Previously unprepared Hello string boundary

Accepted checkpoint: `build/hello-new-boundary-2026-09-22/workflow-v2/` passes
17 commands and seven comparisons in 159.405s, including local and normal-program
defect replay after repair. Twelve local cases and twelve program workloads pass;
unchanged-neighbor and repaired-local evidence reuse with zero work. Integrated
Nix validation passes 14 tests and six repository/SDK gates. See the
[effort and cost account](../../../docs/performance-and-invalidation.md).

The later public-program handoff at `build/component-program-entries-2026-09-23/`
passes the focused workflow below in 93.170s of public commands. A string edit
recompiles one local unit and one program unit, reusing 19 program objects; repaired
program evidence reuses in 1.113s with no compiler or execution work. The defect
and printed replay show `Hello, world!` versus `Xello, world!`. Source export/build,
54 affected toolkit tests and seven repository/SDK/build checks pass. This is a
focused handoff result, not a rerun of the historical twelve-case matrices.

The native setup improvement at `build/component-native-fragments-2026-09-24/`
passes one existing local case and normal Hello startup using the generated hot/cold
entry header described below. Local and program preparation take 0.199s/0.414s;
checks take 8.957s/15.031s and unchanged program reuse takes 1.159s with zero work.
Portable C and the interface are unchanged. Four focused toolkit tests and the
required repository gates accompany this bounded change; the wider matrices are
not repeated.

This is H1's first-time boundary trial for `rpl_mbsrtowcs`, a loop over a mutable
caller cursor, shared conversion state and a synchronous decoder service. The
operation had a partition row but no component declaration, portable C or adapter.
Prior knowledge comprised its address, Hello's caller and the existing conversion
family/program facilities. Disassembly supplied the new implementation; no GNU
algorithm source or prepared component was copied. This was an agent-run trial,
not an independent human usability study.

Read [BOUNDARY.md](BOUNDARY.md) before editing. `component start` retains that file
under `headers/`, alongside the shared `multibyte-objects.h`, generated typed C
interfaces, examples and comparison assumptions. `string-objects.h` adds only the
live cursor. The portable C operation contains the algorithm; `bridge.c`
owns the explicit target ABI/service and program adapters. `driver.c` owns case
transport and observations. None are checker or compiler implementations.

## Fresh preparation

Use `nix develop .#lifting` and the pinned Hello input from the
[handoff recipe](../hello-handoff/README.md). No prior comparison is needed to
prepare this new component:

```sh
python tests/fixtures/hello-string-conversion/prepare.py \
  build/hello-original-input/bin/hello.exe build/hello-string-packages
spaghetti-extractor component start gnu-hello string-conversion \
  --comparison-package build/hello-string-packages/string-conversion \
  --output build/hello-string-draft
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello string-conversion \
  --comparison-package build/hello-string-draft --output build/hello-string-check
```

The recipe uses `ComponentInterfaceIntentV1`, `BoundarySchemaV1` and the documented
`prepare_comparison_package` API. It reuses pinned development-shell tools, the
installed `prepare_routine_image` loader, pointer proxies and native entry/process helpers.
No new artifact format, proof rule, generated-hash edit, compiler mechanism or Nix
expression is needed. Hand preparation remains substantial: declarations, ABI
mapping, service observations, input selection and the program integration adapter.
Preparation no longer imports the quoting fixture's Python code or its unrelated
body declarations. An external operator folder needs this recipe/C/declarations,
the shared `hello-multibyte` object header/license,
plus the pinned original and installed toolkit. The routine image omits original
startup/TLS; its initialization premises remain in the component's assumptions.
All entry/import/process helpers come from `native_adapter_headers`; no sibling
`native/` fixture directory is required by the external operator project.

`native_entry_header` now generates `string-entry.h` from the reviewed hot body
and cold fragment. It reads the entry relocation from the pinned image; the same
`spx_install_string_entry_at(image, replacement)` call works with the routine DLL
and normal executable. `spx_install_string_entry_intact()` retains body-absence
observations. The adapter no longer duplicates relocation arithmetic, protection
changes or trap loops. The decoder observation hook and live-state transport
remain explicit C because they describe the operation's services and observations.

## Edit, diagnose, reuse and integrate

Prepare the existing connected network with `hello-handoff/prepare.py
--program-observer`, as documented in the [program recipe](../hello-program/README.md).
Add the local string workspace as another program entry:

```sh
python tests/fixtures/hello-program/comparison.py \
  build/hello-program-packages/native/quote-slots \
  tests/fixtures/hello-native-quoting/program-runtime.h build/hello-string-program \
  --string-package build/hello-string-packages/string-conversion
spaghetti-headless-wayland python tests/fixtures/hello-string-conversion/walkthrough.py \
  build/hello-string-packages/string-conversion build/hello-string-program \
  build/hello-program-packages/conversion/multibyte-conversion build/hello-string-workflow
```

The walkthrough uses public `component start/check/status` and `candidate export`
commands. It checks one local case containing 192 sequences, one normal greeting
and one unchanged-neighbor case, keeping the edit loop focused. The package still
contains the wider case set below; omit `--case` when that coverage is needed.
It establishes a same-session neighbor baseline, changes only string C, and
checks the affected program with `--dependency-package string-conversion=DRAFT`.
The local and program checks each compile only that changed C unit. Repair can
reuse both results without executing. A deliberately wrong first output word is
caught locally and in actual program output; the printed replay command still
reproduces the faulty program after the draft is repaired. Source export builds
all selected portable C as an ordinary library.

The program's explicit `entries` distinguish string conversion from the quoting
network: neither is declared to call the other. One DLL observer installs both
and compares the additional implicit string state, while actual selected call
counts remain in its diagnostics. The string adapter reaches the already
selected multibyte entry through its existing `decode16` service. These are
experimental executable bindings, not a proof of service compatibility. Every
selected input binds the program comparison, so an edit invalidates integration
without invalidating unchanged local implementations.

The conservative cache binds the entire process environment; another desktop or
shell can require revalidation. All Wine applications, boot and server processes
run inside headless Wayland. The old `program.py` remains for historical bundle
replays; ordinary editing no longer needs its second DLL, separate receipt or
private program runner. The earlier first-boundary trial above retains its
original evidence; this later shared workflow improvement changes no proof or
native-admission standards.

## Coverage and limits

Nine returning cases each contain 192 sequences across retained/generated strings,
three state transports and four limits. Count-only, writing and input/output
overlap preserve cursor, explicit/implicit state and full input/output frames.
Every step records ordered decoder input, size, output and state effects. Three
additional cases capture actual CRT abort after a controlled incomplete service
result. The local oracle retains native decoding in C/Japanese locales; controlled
service behavior is separately labeled.

Hello's main sizes its buffer with `strlen` and invokes writing conversion once.
Count-only/resume/alias cases are local coverage, not normal-program coverage.
The program compares untouched original, instrumented original and selected C
through original startup/TLS, allocation/service observations and actual output.
Help and argument errors do not call string conversion; greeting cases must call
the replacement exactly once. The lower conversion and retained platform services
keep their existing explicit assumptions.

This trial establishes a bounded practical workflow. It does not establish
universal memory summaries, checked compatibility, all possible aliases, native
UTF-8 locale support, general callbacks/concurrency, large-count frontier behavior,
a standalone source project or execution on another architecture. More fixtures
cannot substitute for those delivery steps. Strong qualification remains separate.
