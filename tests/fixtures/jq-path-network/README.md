# Larger jq path/value lifting experiment

Four hand-defined components lift `jv_get`, `jv_set`, `jv_getpath`, and
`jv_setpath` into ordinary restricted C. This exercises loops, recursion,
copy-on-write, aliases, nested objects, slices, errors, and actual jq interpreter
consumers. It is a practical comparison experiment, not a qualified replacement
or a standalone portable jq.

The [assessment](../../../docs/jq-path-network-assessment.md) records results,
measured costs, observed blind spots, and recommended improvements.

The optional `--array-storage-packages DIR` preparation argument now selects
the [authored array storage family](../jq-array-storage/README.md) beneath these
same callers. Its current connected comparison and edit/replay walkthrough passes
through actual interpreter consumers. The baseline below retains native array
services; the selected variant implements array storage/ownership operations in C
while keeping the guarded allocator, foreign destructors and other native services
explicit. Neither variant is a complete portable jq.

With `--resource-checks`, `--string-slice-package DIR` additionally selects the
[authored string-slice boundary](../jq-string-slice/README.md). It removes the whole
native slice body during source execution and uses the same live value transport.
Combined with array storage, its consumer suite includes real interpreter allocation
failure at string slicing and the public edit/replay/reuse/assembly workflow.
Native string constructors and destruction remain explicit lower services.

The [array-search handoff](../jq-array-indexes/README.md) replaces the getter's
retained `jv_array_indexes` service through a new independent boundary. It reuses
the network's declarations/transport, returns via explicit caller refinement,
and demonstrates a C-only follow-up with compiled-neighbor reuse, followed by
normal source-program execution on x86-64 and AArch64. The initial integration
required a shared-tool fix for importing a new transitive supplier; that finding
remains part of the operator-readiness assessment.

## Reproduce

Use the repository's Nix development environment. Prepare from an existing jq
comparison package, retaining its pinned native DLL, import library, compiler,
and Wine tools. This does not need the full extraction or proof pilot.

```sh
jq_path_base=$(nix build \
  './targets#legacyPackages.x86_64-linux.targets.jq.target.array-concat-isolated-comparison-package' \
  --no-link --print-out-paths)
PYTHONPATH="src:$PYTHONPATH" python tests/fixtures/jq-path-network/prepare.py \
  "$jq_path_base" build/jq-path-packages --resource-checks
spaghetti-headless-wayland env PYTHONPATH="$PWD/src:$PYTHONPATH" \
  python tests/fixtures/jq-path-network/walkthrough.py \
  build/jq-path-packages build/jq-path-workflow
PYTHONPATH="src:$PYTHONPATH" python tests/fixtures/jq-path-network/probes.py \
  build/jq-path-packages build/jq-path-probes.json
```

To prepare a local getter from an already selected path network, including its
current storage/string suppliers, use:

```sh
python tests/fixtures/jq-path-network/prepare-local.py build/path-work build/getter-package
spaghetti-extractor component start jq value-get \
  --comparison-package build/getter-package --output build/getter-work
spaghetti-extractor component check jq value-get \
  --comparison-package build/getter-work --history build/getter-checks
```

Run these commands inside the headless lifting shell used above. The recipe needs
the network's retained inputs, not the old standalone supplier packages. It reuses
the getter's boundary and current supplier C/adapters, then explicitly selects the
reviewed native driver and `negative` case. Add other driver-supported cases as
needed for your edit. Return a checked getter edit to the consumer with
`--dependency-source value-get=build/getter-work`. Requirements, shared object
conventions and declared recursion remain visible; this prepares an executable
local comparison rather than independent formal qualification.

Outputs must be new directories. Each Wine workflow uses one headless Wayland
desktop, keeping the environment stable for reuse. The script checks for
`WAYLAND_DISPLAY`; the documented wrapper establishes the headless desktop.
The current runner disposes successfully stopped Wine prefixes; the evidence
needed for replay is in `inputs`, `build`, `cases`, and the JSON receipts.

`prepare.py` calls the same interface, source-package and comparison constructors
used by `sdk.lifting`. It generates interfaces, typed bridges and resolved transitive
selections. This target-specific setup script is fixture machinery, not a new
production command or artifact format. `walkthrough.py` uses the public CLI for
start/check/edit/replay/repair and experimental candidate build/test. It retains
commands, return codes, observations, timings, and receipts. `blindspots.py`
is an optional raw-transport negative control: prepare separate packages without
`--resource-checks` before using it. It checks current unread-header reuse and
adds a reference-count observation after demonstrating a missed raw leak. The
standard instrumented walkthrough detects the leak without that driver edit.

## Review a shared supplier contract in one network workspace

Both `path-get` and `path-set` require `value-get`. After reviewing a revised
`value-get` contract against their call sites, update both named requirements in
one workspace:

```sh
spaghetti-extractor component start jq path-set --comparison-package NETWORK \
  --refine-requirement path-get/get=REVIEWED_VALUE_GET \
  --refine-requirement path-set/get=REVIEWED_VALUE_GET \
  --output build/refined-path-work
spaghetti-headless-wayland spaghetti-extractor component check jq path-set \
  --comparison-package build/refined-path-work --case nested \
  --reuse-comparison PREVIOUS_CHECK --output build/refined-path-check
```

The revised supplier can be authored with the existing
`revise_comparison_package` helper. Requirement names are visible in the generated
component guides. Every affected caller remains explicit; a missing review names
the remaining requirement. This changes declarations and reruns affected concrete
comparisons, without proving contract compatibility. Matching bundled supplier
contracts retain the network's existing implementations, including independent
local edits. The `refine_requirements` Python argument accepts the same qualified
names, and bare names still refer to the package entry.

Ordinary later C edits use `--dependency-source value-get=LOCAL_WORK` and the usual
local/consumer checks. A source-library update after this refinement includes
`value-get`, `path-get` and `path-set` with explicit boundary acceptance: the two
callers retain their bodies but bind the revised supplier contract.

The installed handoff at `build/component-network-refinement-2026-09-24/` clarifies
the getter's owned-reference alias premise and reviews both real call sites.
It preserves the independently edited storage getter, rechecks `nested` with zero
compilations, then runs local edit/defect/replay/repair on the existing `negative`
case. Consumer integration compiles only the edited getter; the source update
preserves neighboring library objects and notes. All Wine execution uses headless
Wayland. This is finite native comparison and explicit review, not proof of every
alias context or a full jq lift.

## Contract-specific resource instrumentation

Pass `--resource-checks` to the preparation command to select the shared
instrumented reference transport. The ordinary C algorithms and driver stay the
same. The constructor uses canonical lifecycle declarations, generated runtime
support and explicit per-operation allowances; it does not add checked-summary
claims to the interfaces. Prepared policies bind these declarations and the
shared representation revision explicitly.

The standard public `component check` command then reports behavioral comparison,
resource diagnostics and contract applicability separately. Discarding
`s->copy(e, root)` in getpath still produces the expected JSON, but now reports an
untransferred reference and a failed zero-escape premise. Repair and retained
replay work without adding a reference-count observation to the driver. Selected
experimental runs check resource findings again during each actual execution.

The bounded observer has 4,096 token slots and 256 nested boundary frames. It
preserves native references when reporting leaks. Slot generations reject stale
or repeated transfer; the observer does not infer native heap lifetime from an
address. Native original/service internals remain unobserved, and immediate jq
values also occupy transport slots. This is boundary instrumentation with explicit
coverage, not a heap-equivalence proof or general memory-safety requirement.
The raw transport remains available to reproduce the original missed-leak control.

## Boundaries and scope

- `get.c`: object/array indexing, missing-to-null, authored numeric index normalization,
  slices, array subsequence lookup, and errors.
- `set.c`: object/array updates, null-container construction, slice growth and
  shrinkage loops, invalid-value propagation, and errors.
- `getpath.c`: iterative path traversal replacing native tail recursion.
- `setpath.c`: recursive path updates, including detachment before recursion to
  avoid unnecessary copy-on-write and the special slice-update path.
- Each unit receives its own generated service/context ABI. Authored code never
  includes `jv.h`, uses a machine address, or reaches into the native heap.
- `native-slice.c`, allocation,
  reference counting, leaf collection operations, and error formatting remain
  explicit fixture services. Their semantics are not checked summaries.
- Raw 16-byte `jv` transport reuses `jq-value-transport`. It does not establish
  logical heap correspondence, unique ownership, or preserved lifetime.
- The contracts say which services borrow and consume. The interface's empty
  checked-interaction lists do not enforce those statements.

`cases.json` holds 106 isolated cases and ten interpreter programs. Path network
packages rerun relevant cases with selected authored callees. The full package
links all four operations and also reads updated paths. Interpreter cases call
`jq_compile`, `jq_start`, and `jq_next` on the actual original library, with its
four exports redirected to the authored operations during execution. Each source
interpreter case requires an observed redirected call; counters are in stderr.
The entry fixture replaces 8/10 bytes containing complete entry instructions;
it does not remove the rest of the old bodies or establish strong native ingress.

Fresh processes construct owned inputs, retain external references, and compare
results, errors, retained contents, and readback. Unique destinations and shared
siblings are explicit setup modes. Unicode travels as ASCII JSON escapes because
non-ASCII PE32 command-line arguments were corrupted in the initial trial.
The ordinary corpus intentionally retains its limited observations so the leak
negative control remains reproducible; the supplemental ownership assay catches
that defect with a root reference-count observation.

## Original and licensing

The oracle is the pinned, patched jq 1.8.1 PE32 `libjq-1.dll`, SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
`prepare.py` rejects another image. Export RVAs are `0x2f806` (`jv_get`),
`0x302b4` (`jv_set`), `0x32ecd` (`jv_getpath`), and `0x323bc` (`jv_setpath`).
The packaged path-depth patch adds the 10,000-element limit. A case checks
rejection at 10,001; accepted paths are sampled up to depth 128, not exhaustively.

`native-slice.c` and `jq.h` are retained jq source/header material. The authored
algorithms were developed against the available jq implementation and native
oracle; this is not a blind decompilation experiment. `COPYING.jq` retains the
upstream notices and permissions.

## Shared service generation

The full path-set network selects value-set and the composed path-get package.
Path-get supplies its selected value-get transitively. Exported bridges and a
generated selection header replace repeated bridge wiring and manually flattened
supplier lists. The retained graph names both consumers of get, the readback
consumer of getpath, and setpath's internal recursive requirement. Recursion is
explicitly synchronous with unproved progress. Conflicting bodies or boundary
contracts reject before compilation; this declared graph is not a checked summary.

An operator can edit a composed path-get package and pass it directly as
`--dependency-package path-get=DIR`; its unchanged get selection follows it.
The retained invalidation report distinguishes changed unit inputs, transitive
integration impact and the separate decision to reuse exact comparison evidence.

`services.py` declares the reusable signatures, resource roles, effects and outcomes.
The comparison-package API generates wrappers and entry bridges through the
existing canonical interface and interaction catalog. `native-services.h` retains
only the nonmechanical slice-record conversion; native error/slice semantics
remain in their existing C files. The preparer, declarations and new C helper
totalled 420 handwritten lines at the F3 checkpoint, versus the previous 584-line
preparer (28% fewer), before the subsequent explicit composition declarations.
Those historical counts exclude the authored algorithms, driver and native semantic
adapters. F6 subsequently moves numeric index normalization into authored
`numeric-index.h`, called by get/set through a binary64 `number` accessor.

Generated service traces are checked for exact contract binding, nested call/return
coverage and declared outcomes. Native semantics, allocation failures and heap
generations remain explicitly unobserved by this instrumentation. The raw transport
option still exists, but current preparation adds service observations; the original
raw missed-leak comparison remains retained separately as historical evidence.

## Scalar capabilities and local assurance

Binary32/64 interfaces render and compile through generated adapters. The authored
`numeric-index.h` handles NaN explicitly and clamps before converting to signed
32-bit indices. `probes.py` checks current binary64 rendering, binary16 rejection
and the resolved transitive graph. Native PE32 and host edge fixtures test signed
zero, subnormals, infinities, quiet NaN payloads, finite conversion and saturation.
These checks do not prove the floating environment or arbitrary arithmetic.

jq's opaque value services still lack a local formal heap rule. Requesting
`--local-contracts` reports this gap separately from source-profile acceptance
and executable comparison. The shared-view optional theorem is demonstrated by
the independent resource-text consumer; it is not an implicit jq proof.
