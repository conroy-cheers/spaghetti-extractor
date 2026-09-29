# jq array concatenation: practical lifting experiment

This is a real shared-value consumer for the practical lifting milestone. Public
preparation, concrete comparison and retained-case replay are implemented. It is
not a qualified component. The [supplier workflow](../jq-array-append/README.md)
adds dependency editing, domain refinement and an explicitly experimental
selected-network build/run using the same comparison infrastructure.

The selected operation is exported `jv_array_concat`, RVA `0x288b3`, in the original
jq 1.8.1 PE32 `libjq-1.dll` produced by the repository's pinned target definition.
Its SHA-256 is `50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
The accompanying `jq.exe` matches the existing target identity
`1d4ccabec8ad11a04f7f45b105809847ca91d018d210746e5a7b4d35b3c84ac6`.
Reproduce that input alone with:

```sh
nix build './targets#legacyPackages.x86_64-linux.targets.jq.input.original' --no-link --print-out-paths
```

This builds the original input, not the target decompilation/proof pilot.
The operation loops over the right array, copies each element into append,
stops on an invalid append result, releases the right array, and returns the
destination. Actual source caller contexts include array addition (`builtin.c`),
path construction (`execute.c`) and library search paths (`linker.c`). These source
contexts have been inspected; their complete machine entry domains are not proved.

## Files and boundary

- `component-interface-intent-v1.json` uses the existing V5 interface compiler.
  It describes two input values, a result, and copy/length/get/append/release/valid
  services. It does not declare a checked heap or ownership summary.
- `concat.c` is ordinary authored component C using generated context/services.
  It passes the existing `portable-component-c11-cbmc-v1` source profile.
- `native-driver.c` is explicit test adapter and object-factory code. It calls
  the actual original DLL and converts the existing 16-byte value representation
  at the generated ABI. It is intentionally outside the authored-C profile.
- `controlled-append.h` checks append arguments against independently cloned
  logical state, records interaction observations and supplies successful writes
  or an injected invalid outcome. The installed `pe32-entry-hook.h` redirects
  the pinned original export during the call, fills its remaining body with trap
  instructions, then restores the complete original bytes.

Inputs must be valid arrays, each contributing an owned reference. References may
share backing storage or nested values. Appending may mutate a uniquely owned
destination or copy shared backing storage. The right input is consumed, and the
result owns its returned value. Retained external references must stay usable and
retain their logical contents. These are currently reviewed expectations exercised
on cases, not a formal lifetime or alias-preservation theorem.

Run the driver as `concat-driver.exe original CASE [MODE]` or `concat-driver.exe source CASE [MODE]`
under Wine inside a headless Wayland desktop, with the original distribution's
DLL directory on `WINEPATH`. Each
invocation constructs fresh values, avoiding shared mutable storage between the
original and source runs. It prints JSON observations of the result, retained
input contents and the right array reference count before teardown.

| Case | Input relationship |
|---|---|
| 0 | Empty right array |
| 1 | Distinct arrays with retained external references |
| 2 | Both inputs share the same array backing storage |
| 3 | Distinct arrays share a nested object |
| 4 | Right input is a slice sharing left backing storage |
| 5 | Destination remains uniquely owned, permitting in-place mutation |

The public package has fourteen cases. Cases `0`–`5` execute real dependencies;
`controlled-0`–`controlled-5` repeat those input relationships with append
intercepted. `fail-first` and `fail-second` use case 1's arrays and inject an invalid
append result on the first or second interaction. The original concat machine
body still executes. Each intercepted append validates its current destination
contents and next item before consuming the arguments and returning an outcome.
Successful responses use real `jv_array_set`; the fixture does not replace all jq
state semantics. These invalid responses are conditional contract cases, **not a
claim that the real allocator returns recoverable allocation failures**.

The driver compares the outcome, final contents, retained right-array reference
count and controlled append interactions, including destination reference counts.
It serializes observations without keeping additional references to live arrays.
An omitted right-array release is detected even on the failure path. Wrong append
items and attempts to continue after a terminal failure exit with a dependency
assumption diagnostic. They are reported as incomplete comparisons, not matching
executions. Real-dependency cases explicitly report unobserved intermediate calls
with `interactions: null`.

## Public edit and replay workflow

Run these commands in `nix develop`, inside one headless Wayland session.
For a scripted walkthrough, use `spaghetti-headless-wayland bash walkthrough.sh`
with the commands below in that script. Keep the same desktop session across
checks intended to reuse evidence: starting a new compositor changes the bound
execution environment and correctly invalidates that reuse.

From the repository development shell (`nix develop`), prepare the package through
the public SDK-backed target artifact and start a writable draft:

```sh
comparison_package=$(nix build './targets#legacyPackages.x86_64-linux.targets.jq.target.array-concat-comparison-package' --no-link --print-out-paths)
spaghetti-extractor component start jq array-concat --comparison-package "$comparison_package" --output build/concat-draft
spaghetti-extractor component check jq array-concat --comparison-package build/concat-draft --output build/concat-check
```

The target uses shared `sdk.lifting.comparisonPackage` and existing V5 interface
and source-package preparation. It builds only the original distribution and the
small executable setup. `source/concat.c` is editable; generated headers, authoring
guidance and `compile_commands.json` are supplied. No formal solver is requested.

Change `index < count` to `index + 1U < count` in `build/concat-draft/source/concat.c`
and check into a fresh output directory:

```sh
spaghetti-extractor component check jq array-concat --comparison-package build/concat-draft --output build/concat-wrong
spaghetti-extractor component check jq array-concat --comparison-package build/concat-wrong/inputs --case 1 --output build/concat-replay
```

Both checks exit 2 and report the first differing result length (4 versus 3 for
case 1). Repair the draft and check into another fresh output directory. The
retained wrong inputs remain replayable after repair. `--json` exposes the full
result. Empty output directories are accepted; existing results are never silently
overwritten. Unknown cases, stale original files, missing observations, compile
errors and timeouts cannot produce a matching result. A timeout is inconclusive.

Each result retains source, interface, fixture, original and runtime files, compiler
dependency hashes, build outputs, case observations and separate preparation,
compiler, link, execution and runtime-setup/teardown timings. Original and source
processes use distinct Wine prefixes; each case constructs fresh C objects. The
runner captures output in files so inherited Wine descriptors do not hold a pipe
open across repeated startup/shutdown delays. This does not establish isolation
of arbitrary external resources outside those prefixes.

To reuse retained evidence when the consumed inputs have not changed:

```sh
spaghetti-extractor component check jq array-concat --comparison-package build/concat-draft --reuse-comparison build/concat-check --output build/concat-reused
```

The command validates the prior receipt, observations, binary, current input
inventory, comparison-engine binding, environment digest and compiler-read files.
Matching evidence is copied with its source receipt and zero new compiler, link,
execution, model and solver calls. Preparation and evidence-validation/retention
time are recorded separately. These are retained observations, not a fresh run
against external state. Changed dependencies trigger an ordinary check with
invalidation reasons and changed input paths. No unchanged-signature compatibility
claim is inferred. A previous mismatch cannot supply passing reuse.

Initial investigations and current public results are retained under
`build/practical-lifting-2026-09-15/`. The provisional `prepare-concat.py` and
`check-concat.py` scripts are no longer needed for this public workflow.

The [append supplier walkthrough](../jq-array-append/README.md) now demonstrates
an actual supplier edit with separate isolated-consumer reuse and integration
invalidation, using the same public commands and generic dependency packaging.

Current limits: sampled inputs and append-only interception. The full original DLL
remains a consumed input; its append body is removed from executable memory during
controlled calls and restored afterward. It remains in the retained original file.
The supplier workflow checks finite input-domain refinements and can build an
experimental execution manifest. Neither supplies a formal shared-jv composition
rule, allocator-failure guarantee or machine binding/whole-application coverage
proof. Passing JSON comparisons do not prove all heap contents,
lifetimes, intermediate effects or portability. The native-layout adapter is
explicitly not a portable replacement of libjq.

The [shared value representation experiment](../jq-value-transport/README.md)
uses the same authored source with raw values or bounded owned handles, including
explicit replacement-group selection and mixed-representation rejection.

The input setup now checks the declared logical contents and whole-array, slice
and nested-object aliases before either implementation is invoked. It also checks
the unique destination case. Negative controls under `validation-v1` replace
shared inputs with equal-content independent values and require a fixture failure.
