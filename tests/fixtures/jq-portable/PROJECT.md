# Portable jq source project

This source-assisted project links the selected exported C components with the
pinned jq 1.8.1 source libraries and runtime adapters. Selected original operation
bodies are removed. The selection, binding guides and actual link map determine
which implementations remain; the presence of an old source file or cached object
does not establish that it is linked. A prepared project can be partial. A final
delivery also includes `DELIVERY.md` and its reviewed library inventory.

Start with [COMPONENTS.md](COMPONENTS.md) to open one component's portable binding
guide. It links the actual generated C entry, selected service symbols, declared
suppliers, shared support files and private-state backend headers. Its boundary
guide separately records the original comparison setup and assumptions.

Run `make -j2` with a C11 compiler, GNU make and binutils. The delivered project
requires neither the extractor, Python, Nix, Wine nor the original executable.
Configure is generated during preparation. Override `CC`, `AR`, `RANLIB` and
`CONFIGURE_FLAGS=--host=aarch64-linux-gnu` for cross compilation. Use a separate
project copy or `make clean` when changing toolchains/flags. `LDFLAGS=-static`
produces a standalone Linux executable where the toolchain supports it.

`./jq` uses normal process startup and the selected CLI, compiler and interpreter.
With the `cli` component selected, the shared output provider preserves Windows
text output by default and switches to byte output with `--binary`. Program
receipts record actual arguments and compare output without normalization.
The selected runtime profile and its limits are retained in the component boundary.
`SPX_COMPONENT_COUNTS=/absolute/file.json`
optionally writes selected entry counts at normal process termination, separate
from program stdout and stderr. Signal termination does not produce that report.
`make live-values` builds a separate diagnostic consumer of the unchanged jq C
API; it observes shared contents, aliases, reference counts and view releases.

`make -f Makefile -f diagnostics/failure.mk failure` builds an optional allocation
failure consumer. It reuses the component/backend objects and links separate GNU
allocator wrappers; normal `jq` and `live-values` omit those wrappers. Run
`./failure string-copy`, `string-empty`, `string-invalid`, `array-create`,
`array-set`, `array-grow` or `program-string`. The last case enters the real jq
interpreter. The real guarded allocator invokes the registered handler and
`longjmp`; the fixture retains live aliases and records references, requested
bytes and residual allocations after cleanup. Only a next-`malloc` failure is
injected, not physical memory exhaustion or an arbitrary allocation failure.

Handler registration precedes observation. The program case also initializes
numeric conversion first: its per-thread context contains nine pointers, so
comparing cold residual bytes would compare different object representations.
`./failure program-string-cold` intentionally leaves this dependency cold. It
reports an extra 36 bytes on PE32 and 72 on the tested 64-bit hosts. Keep that
physical difference explicit; it is not silently normalized into a passing case.
Diagnostic serialization is excluded from lifetime totals. Nonzero residuals
preserve the original's observed lost references after nonlocal failure; they
do not mean that the fixture reclaimed every object or proved heap safety.

The pinned PE32 CLI passes an import thunk as its input callback. The DLL sees a
different address, which affects `input_filename`, `input_line_number` and fatal
error reporting. The explicit `import-runtime` adapter preserves that identity
distinction. Its redirected assertion path uses the shared output provider for
byte text or UTF-16LE binary diagnostics, stream flushing and exit 3. This is target behavior, including
the original defect; statically linking upstream source alone silently changes it.
Other CRT assertion sites and native terminal presentation are outside this scope.

Each `lifted/components/<name>` retains source, interface, requirements and the
comparison's assumptions. Shared storage layouts live in the exported storage
sources; bindings reuse them. The application adapters preserve actual live
objects, aliases and reference counts. They do not reconstruct a heap from
addresses. The path/string transport copies every byte of a host `jv`, including
its real pointer; static assertions check size/layout. This backend/transport
change needs its own execution evidence. It does not inherit the PE32 fixture's
token instrumentation or turn declared lifecycles into proofs.

Edit a component here or in its comparison workspace. To import C edited here, use
`component start jq COMPONENT --comparison-package LOCAL_PACKAGE --reuse-source
PROJECT/lifted --output DRAFT`. The original local package still supplies its
oracle and adapters; the selected C becomes an unverified draft. Header, contract
and source-layout changes use authoring/refinement instead. Compare and repair
the draft with `component check` inside a headless Wayland desktop. From the
lifting shell, apply the matched result and reviewed bindings together:

```sh
spaghetti-extractor candidate apply jq --project PROJECT --comparison RESULT \
  --component NAME \
  --assembly-command 'python /absolute/path/to/jq-portable/refresh.py {project}'
```

Use the same operation for implementation edits, changed entry sets, and provider
replacement. Add `--accept-boundary-change NAME` for an added or changed boundary,
and supply binding choices when needed. Add `--check-command` arguments for the
build and headless program comparison to require them before publication. Commands
run in a staged project; use absolute script paths. Failure preserves the current
project and retains the proposal for inspection. Successful publication retains
the previous project for recovery. Library-only export remains available through
`candidate export`.

The selected unit and any explicitly selected dependencies are refreshed; the
remaining components and their provenance stay in the library without requiring
their comparison workspaces. Compatible local C edits normally compile only the
changed objects and relink. Boundary or representation changes require reviewing
affected adapters and exercising their program workloads. A stable signature is
insufficient. If reviewed binding/build edits conflict, inspect the proposal,
merge them, and use the recipe's `--keep-reviewed FILE` choices. The assembly
recipe itself needs no original executable or native comparison directories.

For a new entry, pass `--bindings FILE` to preparation or refresh. This JSON maps
component names to reviewed `native_symbol`, `backend_file` (such as `src/jv.c`),
`headers` (destination filename to file relative to the JSON) and optional
`service_symbols` (service name to its portable adapter symbol). A component may
specify only service overrides when its entry already exists. The recipe copies
headers into `bindings/` and retains selected choices in `portable-project.json`.
Later refreshes need only the project; the original JSON/header locations can be
removed. The recipe README has a complete array-search example. Grouped `assembly`
choices declare entry providers, C adapters and reversible backend replacements;
the refresh reconciles entry changes and moves. Services and layout changes still
require reviewed integration. These source choices do not carry comparison or
proof authority; run affected program workloads.

Optional `backend_symbol` names a removed body separately from the generated
entry, allowing an ordinary C wrapper to preserve its platform ABI.
`backend_headers` maps a backend `src/*.c` file to reviewed headers included after
its private definitions. Those headers are retained beside the backend source;
local edits invalidate program validation and rebuild that translation unit.
Generated binding guides refresh with these choices, and documentation-only
changes do not request new execution.

The execution profile comes from the selected component boundaries and program
receipts: live well-formed objects, 32-bit `int`, 16-byte `jv`, and the recorded
target-width allocation frontier. Some components retain sequential assumptions;
the selected test runner and numeric runtime separately exercise their pthread
lifecycle. That does not make shared jq states or every runtime service safe for
concurrent use. Filesystem, terminal, environment, locale and platform behavior
beyond the stated profile remain unqualified. Source assistance, generated parser
reuse, tested behavior and stronger proof claims remain separate.

`portable-project.json` records source/backend/binding provenance at preparation
and recipe refresh. Explicitly merged files have separate actual hashes, while
the generated baseline remains available for subsequent edit detection. Source
updates have their separate export receipts. An unvalidated
prepared project is not evidence of successful program execution. Keep retained
program results alongside the project. Upstream licenses remain in `backends/jq`
and the exported components.
