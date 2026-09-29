# jq slice and test-runner continuation

The existing workflow now supplies the retained slice-range helper and the
complete `--run-tests` implementation. This is further practical lifting
progress, not completion of the jq goal. Path canonicalization and the explicit
library/standalone-delivery audit remain. No significant tooling blocker was
found, and no checker, compiler infrastructure or proof machinery changed.

## Two ordinary component changes

The value-runtime boundary gains `slice_bounds`, bringing its native entry set
from 40 to 41. `slice.c` is readable, source-assisted C preserving consumption,
codepoint versus array lengths, null defaults, negative/fractional bounds,
NaN/infinity handling, error results and output writes. Output pointers may alias;
errors leave them untouched. The native adapter implements the reviewed private
ABI: hidden result in EAX, both values and integer pointers on the stack.

All 63 native cases match. They retain the previous value-runtime workloads and
add direct range cases with retained input aliases and output sentinels. The old
native helper is disabled. Standalone path get/set adapters keep their existing
interface: `native-slice.c` now transports to the selected `parse_slice` entry
instead of retaining its copied implementation. The older standalone fixture
still retains its reference helper when that provider is not selected.

The new `test-runner` boundary supplies `jq_testsuite`. Its ordinary C separates
test-file/worker execution from value checks, with decimal and pthread branches
explicitly enabled. It reuses the shared Windows file provider, process stdin
decoder and jq services. The three workers each own a jq/parser instance and join
before returning. Named files retain the original lifetime until CRT shutdown.

All 18 native cases match through actual program entry, including test failures,
skip/take behavior, verbose execution, missing files, CRLF and Ctrl-Z. The observer
checks actual stdout/stderr, exit status and successful thread creation/join
counts; successful cases create and join three workers. The whole old test-runner
object is disabled, including helpers. An untouched-original control checks that
the observer does not change behavior. No single-thread allocation observer is
used across concurrent workers.

These components are source-assisted from pinned jq 1.8.1, with its license
retained. They do not establish autonomous recovery from an unavailable source
tree, universal equivalence or strong activation authority.

## Integration and reuse

Both changes use the installed `candidate apply` operation. The first assembly
attempt encountered duplicate braces in the original `#ifdef __MVS__` pthread
branch. The ordinary C recipe now records the exact selection of the existing
non-MVS spelling before reversible function retirement. Failed proposals remain
available and left both working projects unchanged. The tool did not need a new
preprocessor rule.

The successful x86-64 and AArch64 projects each match **308 CLI and 32 live-value
cases**, including named-file and stdin test-runner use. Their link maps show one
`parse_slice` and one `jq_testsuite` provider. The old `jq_test.o` has no functions;
`native-slice.o` contains only the transport wrapper.

The x86-64 project preserves all 40 neighboring component records and 517 exported
files; AArch64 preserves 41 records and 523 files. Existing objects retain both
bytes and mtimes: 187 on x86-64 and 188 on AArch64. Twelve objects change or are
added on each host. Their selection contains 42/43 components respectively; the
extra ARM component is its previously selected hash provider.

| Cost | x86-64 | AArch64 |
| --- | ---: | ---: |
| Standalone incremental build | 0.766 s | 11.035 s |
| Normal program comparison | 15.490 s | 29.370 s |

Native value-runtime preparation/compiler/link costs are 0.026/0.736/0.064 s;
its 126 executions sum to 10.283 s. The repaired test-runner comparison reuses
two objects after fixing an unused-header warning; preparation/compiler/link
costs are 0.012/0.229/0.064 s and its 54 executions sum to 3.512 s. Wine startup
wall time is recorded separately (3.661/8.389 s). Model, solver and pilot rebuild
costs are zero. These are retained measurements, not performance guarantees.

## Remaining delivery work

The linked jq backend now contains `jq_realpath`, three forwarding accessors,
the generated lexer and dtoa conversion library. decNumber and Oniguruma remain
explicit library dependencies. An old parser object still exists in the build
directory but is absent from the link map; it is not an active provider.

A small retained native path probe confirms why `jq_realpath` still needs work:
Windows `_fullpath` lexically canonicalizes nonexistent paths and produces drive
and backslash spelling, while the existing POSIX backend uses `realpath`. Replacing
that one call also requires compatible file lookup and dirname/basename services
for module loading. This is ordinary shared-runtime work, not evidence that the
component interfaces need another semantic engine. The probe is investigation,
not a delivered path provider. Path/runtime scope must remain explicit.

Final completion also needs a reviewed library-reuse inventory and a fresh
standalone source delivery audit. Additional component counts do not substitute
for that work. Finite tested behavior, assumptions and proved properties remain
separate.

## Reproduction and evidence

Recipes are in `tests/fixtures/jq-value-runtime/` and
`tests/fixtures/jq-test-runner/`. The retained root is
`build/jq-final-support-lifting-2026-09-27/`:

- `values/checked/` and `tests/repaired/`: native comparisons and exact inputs;
- `program/` and `arm-project/`: current standalone source projects;
- `apply.py`, `host-bindings.json`, `arm-bindings.json`: combined public apply;
- `*-assembled-build/` and `*-assembled-run/`: successful program evidence;
- `path-probe.c`, `path-probe.jsonl`: native path investigation;
- `verify.py`, `result.json`, `validation.json`, `tree-audit.json`: receipt,
  neighbor reuse, repository-check and dirty-tree audits.

Every Wine execution used a headless Wayland desktop. Metadata refresh,
repository metadata, production Python lint, format registry, fixture Python
syntax and whitespace checks pass. Existing unrelated dirty-tree work is retained.
