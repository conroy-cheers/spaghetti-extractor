# jq CLI and shared output-runtime continuation

The existing workflow now replaces jq's command-line implementation through real
process startup and exports it into both standalone source projects. All 48 native
CLI scenarios match; x86-64 and AArch64 each match 277 CLI cases and 32 live-value
cases. This also resolves the previously retained default-output CRLF difference.
Full jq lifting remains incomplete; no significant tooling blocker was found.

## Boundary and ordinary C

The [CLI fixture](../tests/fixtures/jq-cli/README.md) owns argument parsing, option
handling, the processing loop, callback registration and exit policy. Its 622
lines of C are source-assisted from pinned jq 1.8.1. It borrows live UTF-8 argv,
owns one jq context and input state, keeps callback data alive until teardown,
and terminates through an explicit runtime service.

The pinned `jq.exe` SHA-256 is
`1d4ccabec8ad11a04f7f45b105809847ca91d018d210746e5a7b4d35b3c84ac6`.
Native replacement disables `umain` at `[0x245e,0x490c)` and its private helper
range `[0x1440,0x245e)`. Windows startup, wide-argument conversion and TLS remain
original. The existing `program_driver` runs an untouched control, observed
original, and replacement for every case. Their arguments, stdout, stderr and
exit status compare exactly. Each source run checks one selected entry call and
the intact traps over the removed original bodies.

Locale, regex-depth setup, stream modes, terminal handling, callback identity and
termination are ordinary C runtime adapters. Native comparison retains the
original jq libraries. Standalone execution uses the previously selected lifted
network. The version and configuration output preserve the original target's
observable metadata; the actual host build is separately recorded in `build.json`.

## One stream policy for all consumers

The reusable [Windows-output library](../tests/fixtures/portable-runtime/windows-output.c)
supplies stdout and stderr together. Its Windows backend preserves the original
CRT operations. Its Linux backend uses cookie streams to translate every LF to
CRLF and to forward buffering, errors and close to the underlying streams.
`--binary` flushes pending output before changing the shared mode. Neighboring
serializers and diagnostics use the same FILE transport without edits to their C.
The existing input provider continues to handle Windows text-input behavior.

The first standalone run caught two meaningful differences: the pre-existing
assertion adapter always emitted UTF-16LE. That matched the original in binary
mode, but the original emits byte text with CRLF in default text mode. The shared
runtime now carries both observed behaviors. The callback identity defect itself
is preserved; the lift does not silently repair the original jq assertion.
The initial failed proposal remains retained and did not change the working
project. The corrected proposal passes both architectures.

The first native observer also missed these cases because CRT abort bypasses
normal `exit`. A second ordinary import hook observes the actual CRT
`ExitProcess` call and forwards it. The untouched control still checks observer
transparency. No expected exit value or output is substituted by the comparison.

## Assembly and reuse

`candidate apply` still stages source export, binding changes, build and program
checks before publishing. The CLI's target adapter retains and normalizes the
backend entry signature, whose Windows and host spellings originally straddled a
preprocessor branch. The existing reversible retirement then removes that body
and the original helpers. The compiled backend `main.o` has none of those
definitions; the final executable has exactly one selected `main`.

Two small jq-recipe improvements support this process entry: library consumers
exclude the component providing `main`, and backend-body auditing includes the
separately linked `main.o`. These use declared entry providers. The program-run
fixture also accepts explicit retained runtime files for both sides. No tool
internals, semantic engine, compiler or proof machinery changed.

| Evidence | x86-64 | AArch64 |
| --- | ---: | ---: |
| Selected components | 39 | 40 |
| Prior component records retained exactly | 38 | 39 |
| Prior exported component files retained exactly | 481 | 487 |
| Existing objects retained by bytes and mtime | 175 | 176 |
| Changed or new objects | 8 | 8 |
| Build wall time | 0.465 s | 5.724 s |
| Program cases matched | 277 | 277 |
| Live-value cases matched | 32 | 32 |

The eight objects are backend `main`, the CLI entry/runtime adapters, shared output
and assertion adapters, entry observations, and two authored CLI objects. All
neighboring component implementations and their retained comparison records are
unchanged. ARM's separate existing string-hash component explains the component
count difference; both projects retain their selected providers.

The final native check spends 0.011 seconds preparing, 0.197 seconds compiling two
changed adapter objects, 0.064 seconds linking and 0.030 seconds preparing the PE
import. The three Wine sessions start in 7.917 seconds wall time; all 144 process
executions take 9.225 seconds summed. Initial compilation covered four translation
units in 0.276 seconds. Model, solver and pilot-rebuild costs are zero.

## Scope and remaining work

The practical source profile is satisfied. Formal eligibility remains incomplete
and formal checking was not requested; neither these cases nor an opaque pointer
establishes universal equivalence or activation authority.

The exercised delivery profile is redirected file/pipe I/O with UTF-8 arguments.
The Linux output backend requires libc cookie streams. Interactive console APIs,
arbitrary Windows namespaces, code-page locales, signals and exhaustive allocation
or I/O failures remain outside this evidence. Native and portable workloads have
exact retained inputs and output bytes; the comparator does not normalize them.

Remaining source/runtime dependencies include Unicode, bytecode and source-location
helpers, path services, seed/TLS state, generated frontend support, the internal
test runner and numeric/regex libraries. These need explicit lifting or library
reuse decisions and a final delivery audit. Component counts are not a full-jq
completion measure. The goal remains active.

Retained evidence is under `build/jq-cli-lifting-2026-09-27/`: `cli/authoring/` and
`cli/final-comparison/` are editable; `cli/final/` is the native receipt;
`program/` and `arm-project/` are delivered source projects; `host-final-*` and
`arm-final-*` retain builds and workloads. `host-integrated-run/` records the
diagnosed text-mode assertion mismatch. `result.json`, `validation.json` and
`tree-audit.json` record the final checks and preservation of unrelated edits.
