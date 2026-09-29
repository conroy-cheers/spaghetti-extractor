# Stateful conversion beneath the actual Hello quoting consumers

This hand-defined component groups complete `mbrtoc32`, `rpl_mbrtowc`,
`rpl_mbsinit` and `mbszero` operations. Its ordinary C owns UTF-8 decoding, saved
prefixes, continuation repair, resets and the two distinct implicit conversion
states. It composes beneath the [quoting engine](../hello-quote-engine/README.md)
and the [native callers](../hello-native-quoting/README.md) through existing
interfaces, C adapters, dependency selection and experimental comparison. No
solver model, production checker or new artifact format is required.

The algorithm reference is GNU Hello 2.12.3's gnulib conversion sources, including
Bruno Haible's UTF-8 decoder. `COPYING.hello` retains the GPL license for this
source-assisted implementation. The original PE32 routines, not a second copy of
the authored algorithm, are the comparison oracle.

The accepted checkpoint is `build/hello-multibyte-2026-09-22/workflow-v1/`:
28 public commands and 25 comparisons pass in 378.236s, including the eight-unit,
63-case experimental assembly. `packages-v3/`, `engine-packages-v2/` and
`native-packages-v1/` are its prepared inputs. The independent original-runtime
engine is in `controlled-engine-packages/`; it does not select the conversion C.
The separate seven-unit regression passes 21 cases and the actual-terminal
regression nine. Nix validation passes 13 tests across three shards and six
repository/SDK gates in 25.735s. No pilot or toolchain rebuild was required.

A compatible edit takes 16.486s locally, 42.263s through the complete engine and
17.178s through native callers, compiling one unit in each check. Unchanged engine
reuse takes 4.460s with zero compiler/link/execution/model/solver work. The local
changed C compiles in 0.032s; Wine startup and execution dominate the native loop.
These are development measurements, not a controlled benchmark. Retained
`costs.json` separates those phases from evidence handling.

## Complete operations and state

The pinned original executable is SHA-256
`71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`.
The retained transfer-plan inventory contains 144 transfers in these manually
reviewed ranges. Inventory and finite execution are not checked machine coverage.

| Public operation | Owned original RVA ranges | Boundary |
|---|---|---|
| `decode32` | `[6df3,7211)`, cold `[14658,1465d)` | Nullable output/input/state; target byte count and result; UTF-8 prefix state or selected 16-bit conversion |
| `decode16` | `[7214,7315)` | Nullable output/input/state; repair the lower CRT's continuation count and incomplete-output behavior |
| `initial` | `[7318,7331)` | Observe all four current state bytes; null denotes an initial state |
| `reset` | `[2b28,2b35)` | Clear all four live state bytes |

The original implicit states at `30314` and `30318` become distinct explicit
context fields. The bridge relates those fields to the actual cells for native
execution. Nullable state parameters select the appropriate cell. A 32-bit
conversion delegating to 16-bit conversion passes its already selected state;
it does not switch to the 16-bit operation's implicit cell. Private C calls within
this component do not become synthetic production interfaces.

State and byte-span objects are live call-scoped proxies. Output words can alias
state or input storage, and the adapter preserves that identity and write order.
Output words are aligned live C objects; input spans must be readable and bounded.
The target state representation has four bytes and the native bridge is PE32
little endian. A different platform must supply the corresponding representation
and services, including any byte/word alias relation; this example does not prove
arbitrary host `mbstate_t` or byte-order compatibility.

The boundary retains four synchronous services: charset selection, lower CRT
16-bit decoding, errno assignment and invalid-state termination. C code repairs
continuation behavior around the lower decoder and implements UTF-8 directly.
The native lower decoder, locale selection/classification, process startup and
Win32 runtime have not thereby become portable. The declarations and adapters
are not checked memory, effect or lifetime summaries.

## Native locales and a separate UTF-8 service context

The retained CRT accepts `.65001` for some locale categories but leaves
`LC_CTYPE=C`; `locale_charset()` returns `CP1252` and the width remains one.
`build/hello-multibyte-2026-09-22/probe.log` records the actual locale string and
conversion result. Naming that locale does not establish UTF-8 execution.

The new matrix therefore separates three contexts:

- Native `C` locale, with actual charset and CRT services.
- Native `Japanese_Japan.932`, including real two-byte conversion and continuation.
- Explicit controlled UTF-8: both sides receive `UTF-8` from the charset service
  and four from the width service. The original decoder and its control flow are
  still native. This is conditional execution under supplied services, not evidence
  of native CRT UTF-8 support.

The source side traps all four original conversion bodies and the cold fragment,
apart from the entry jumps into authored C. The bridge checks those bytes/jumps
and records per-operation entry counts. Some consumer cases have zero conversion
calls; their selection alone is not execution coverage.

## Observations and deliberate defects

The 24 returning cases cover both decoding APIs and four chunk sizes in all three
contexts. Each has 288 sequences: 48 retained/generated byte streams and six
output/state arrangements. Every sequence observes zero-length input, incremental
conversion, null-input reset semantics, initial-state tests and explicit reset.
Returned counts, errno, output, explicit state, both implicit cells, input aliases
and adjacent state frames are retained. The UTF-8 cases also check malformed state
counts and the distinction between empty input and invalid state.

Three additional cases start with a malformed saved prefix that reaches native
abort. An ordinary C observer snapshots output/state/errno at the abort import and
forwards the real CRT function. The existing child-process supervisor compares
exit code and binary output, rejecting timeout, truncation or capture failure.
Cases cover present, absent and state-aliasing output. In the retained matrix all
three exit with code 3, including the write before termination. Original startup,
arbitrary signal handlers, callbacks, concurrency and reentrancy remain outside
the scope. These are finite observations, not a strong proof.

The quoting-engine integration adds a fourth locale case (controlled UTF-8) to its
existing matrix: 220 cases and 24,640 transformations per side. Native integration
executes the 21 existing quoting sequences in each of the three contexts, for
63 cases. The same selected C is used at both integration levels.

The public walkthrough makes a compatible conversion edit, rechecks both affected
integration levels and reuses the independent engine comparison with original
runtime services. That unchanged check has no selected conversion C dependency;
its reuse is finite evidence reuse, not a body-independent composition proof.
Replacing decoded characters with zero is diagnosed locally, through the quoting
engine and through actual native callers. All three faulty inputs replay after
repair. A second defect clears only the state's count byte: decoded characters
can still match while saved-prefix bytes and initial-state observations differ.
The local comparison detects and replays that state-only defect too.

## Reproduce through the public workflow

Use `nix develop .#lifting` and the
[fresh connected recipe](../hello-handoff/README.md) for a setup without any
previous comparison directory. These component preparation commands also accept
the original and output alone to use that shell's pinned tools. An explicit
retained environment package, as below, remains supported.
Preparation requires the pinned Hello executable separately and never rebuilds it:

```sh
PYTHONPATH=.:src python tests/fixtures/hello-multibyte/prepare.py \
  /path/to/retained-pe32-comparison/inputs /path/to/original/hello.exe build/hello-mb
PYTHONPATH=.:src python tests/fixtures/hello-quote-engine/prepare.py \
  /path/to/retained-pe32-comparison/inputs /path/to/original/hello.exe build/hello-mb-engine \
  --multibyte-package build/hello-mb/multibyte-conversion
```

Prepare the native package with the normal native `prepare.py` recipe, supplying
`--quote-engine-package build/hello-mb-engine/quote-buffer` and the cleanup,
realloc and checked-allocation packages. It derives the selected conversion group
from the existing dependency graph and includes its runtime adapter automatically.
No second selection list or hand-edited digest is required. Prepare an independent
original-runtime engine package with the engine recipe and no multibyte argument.

Within one headless Wayland desktop, run:

```sh
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=.:src spaghetti-headless-wayland \
  python tests/fixtures/hello-multibyte/walkthrough.py \
  build/hello-mb/multibyte-conversion build/hello-mb-engine/quote-buffer \
  build/hello-mb-native/quote-slots build/hello-original-runtime-engine/quote-buffer \
  build/hello-mb-workflow \
  --component-comparison allocation-grow=/path/to/growth-check \
  --component-comparison preserve-errno-free=/path/to/free-check \
  --component-comparison quote-cleanup=/path/to/cleanup-check \
  --component-comparison allocation-reallocate=/path/to/reallocate-check \
  --component-comparison checked-allocation=/path/to/checked-allocation-check
```

Neighbor checks must bind the implementations selected by those packages. The
recipe rechecks their exact retained inputs through public commands, then uses
them in the explicit experimental assembly. All Wine applications, boot and server
operations remain inside the desktop. Preserve cross-compiler linker dependencies.
The earlier native walkthrough also accepts extra transitive local checks using
the same `--component-comparison ID=PATH` spelling.

Missing executable state transport and observed discrepancies still prevent a
matching result. Formal checking is not requested here; experimental receipts do
not grant strong qualification or authorize a complete portable Hello claim.
