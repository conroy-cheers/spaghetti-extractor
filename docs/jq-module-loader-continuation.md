# jq continuation: module loading and filesystem portability

The subsequent [file-runtime continuation](jq-file-runtime-continuation.md)
resolves the recorded input/path gap through ordinary C and continues into two
further input components. The stopping point below is historical evidence; it
was runtime implementation work, not an established limitation of the tooling.

The 2026-09-26 continuation delivers a module-loader replacement using the
installed [stateful-component workflow](stateful-component-workflow.md) toolkit.
The component matches native jq, and the standalone projects pass an expanded
program suite on two architectures. The attempt stops at a confirmed shared
runtime gap: the portable projects use host filesystem and C stream semantics,
which differ from ordinary Windows file behavior.

No checker, compiler, artifact format, proof rule or source-assembly infrastructure
was changed. Preparation reused retained inputs and incremental projects; no
pilot rebuild was required. This remains source-assisted partial jq lifting.

## Delivered module loader

`module-loader` groups `load_program` and `load_module_meta`. Program loading
borrows a jq runtime and source location and returns an owned linked compiler
graph on success. Some failure paths leave the output pointer untouched; the
entry adapter preserves that behavior. Metadata consumes a module-name value and
returns an owned JSON or invalid value.

The implementation retains recursive import order, the per-call cache of module
names and definitions, repeated-import reuse, separately bound data imports,
search-path handling, errors and cleanup. Existing parser, IR construction and
binding, values, allocation, paths/files and diagnostic services remain explicit
dependencies. The opaque C records retain reviewed representations and ownership;
their signatures alone do not establish those premises.

The authored implementation separates path search into `locate.c` and dependency
loading/ownership into `loader.c`, with a private header. These helpers do not
become synthetic component APIs. The implementation has 492 lines of C and 18
lines of authored headers. Raw `strdup`/`free` calls use the existing unguarded
allocation/free services, retaining their failure behavior and sharing the
allocator with neighboring components. No module-wide writable state is needed.

**All 25 native consumer cases match.** They cover two jq contexts and repeated
starts, nested and diamond imports, repeated aliases, the alternate module-file
locations, JSON/raw data imports, search paths, optional and missing imports,
invalid names, malformed libraries/data, module metadata and cleanup. Successful
nested/diamond cases are checked to execute and return their expected values;
matching compile failures are not counted as successful recursive composition.

The initial fixture used relative library directories, which made those two
recursive cases fail on both sides. Canonicalizing the directories as the real
CLI does, and naming the nested import relative to that search root, corrected
the fixture. Both corrected cases match after the C refactor.

Original bindings pin DLL SHA256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
The source side redirects both entries and traps the original private path,
search and loading bodies. Nineteen image-bound C helper wrappers reuse existing
IR/runtime facilities. The driver creates the same module files in each private
working directory, controls the CRT environment, and replaces only each exact
working-directory prefix in diagnostic observations with `<fixture>`. File names,
line numbers, messages, values, callbacks and residual allocation lifetime remain
compared. These finite cases do not establish arbitrary import cycles, allocation
failures, concurrent filesystem mutation or all Windows path forms.

The refactor and corrected fixture compile three translation units and reuse
three. Compiler time is 0.544 seconds, linking 0.064, case execution 6.612 and Wine
startup wall time 6.282; model/solver work is zero. Recipe execution is retained
separately. Manual boundary analysis, native-binding review and fixture authoring
were not separately timed and are not represented by these execution costs.

## Standalone integration

Partial source export adds the loader to the existing project, preserving all
**28 neighboring component records** and their files: 318 host and 315 AArch64
component files. The existing assembly binding supplies both native entries.
The old loader entries and private loader functions are absent from the backend
archive; normal execution reaches the replacement 107 times in each CLI suite.

Both **x86-64 and AArch64 under QEMU match 103 normal CLI cases and 32 live-value
scenarios** against the original PE32 program. The CLI suite includes 17 new
module cases. Each incremental build changes six objects and takes 0.765 seconds
on the host or 4.485 seconds for AArch64. All Wine applications use a headless
Wayland desktop.

Those results cover the recorded files and workloads. They do not mean arbitrary
module files behave identically across the Windows and host runtime backends.

## Confirmed stopping point

A further normal-entry case imports two raw data files and queries metadata for
`MATH`, while the retained module is named `math.jq`. Both programs run
successfully, but their observable results differ:

| Input or operation | Original Windows jq | Current portable source project |
| --- | --- | --- |
| Raw file containing `one\r\ntwo\r\n` | `one\ntwo\n` | Retains CRLF bytes |
| Raw file containing `before\x1aafter\n` | `before` | Retains Ctrl-Z and the following bytes |
| Metadata lookup for `MATH` with `math.jq` present | Finds the module | `module not found: MATH` |

The same portable observation occurs in the **previous host build**, before this
loader replacement, and in the current AArch64 build. The discrepancy therefore
predates the component edit and is not an architecture-specific lowering error.
The failing case remains separate from the passing 103-case suite; no comparison
field is removed or normalized to turn it into a match.

The source project explicitly assumes host startup, filesystems and streams.
`jv_file.c` uses host `open`/`fdopen`/`fread`; the loader and `util.c` use host
file-existence and path-resolution behavior. Existing Hello facilities cover a
scoped output/encoding backend, not these input-file and namespace semantics.
There is no reusable Windows-compatible file-input/path provider wired into the
jq source project.

This is a runtime/backend coverage gap, not a failure of C admission or an
inexpressible component boundary. Ordinary C adapters and the current assembly
facilities can carry a solution. A faithful portable jq nevertheless needs shared
file/path and text-stream services used consistently by the loader, file reader
and CLI. Rewriting literal module names or stripping characters in each component
would leave other consumers inconsistent. The next work should establish that
reusable backend with an explicit supported filesystem/text-mode scope and retain
host-native behavior as a separately selected policy. It does not require a new
proof engine or an architectural restart.

Per the instruction to stop at a significant limitation, this attempt stops
before implementing that backend or extending more components around the same
unresolved runtime dependency. Full jq recovery and unrestricted portability
remain incomplete.

## Retained handoff

`build/jq-linker-lifting-2026-09-26/` contains:

- `linker/workspace/`: editable loader/search C and the comparison boundary.
- `linker/refactored/`: matching native evidence, exact inputs and observations.
- `program/`, `arm-project/`: standalone source projects with 29 selected
  components; corresponding build/run directories retain the passing workloads.
- `filesystem-probe/`: the failing normal-entry case against original Windows jq.
- `filesystem-isolation/`: reproduction with the previous host and current ARM
  builds, confirming the shared runtime gap.
- Preparation/refactoring/integration recipes, module files, case lists and
  `result.json` with costs, scope, file identities and the dirty-tree audit.

Repository changes in this continuation are documentation only. No broad proof or
repository test campaign was rerun for unchanged tool internals; validation was
the public source check, actual native/program comparisons, incremental builds,
backend-symbol checks and `git diff --check`. Existing proof standards and prior
qualification limitations are unchanged. Unrelated starting work is preserved.
