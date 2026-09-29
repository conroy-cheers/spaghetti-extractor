# New jq string-slice boundary through real consumers

This trial replaces the path network's retained `jv_string_slice` dependency with
ordinary C. It reuses the existing service definitions, borrowed C objects, jq
value transport, allocation observer, nonlocal handler and dependency selection.
The original is the pinned jq 1.8.1 PE32 library, SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
The whole 827-byte native body at RVA `0x29e0a..0x2a145` is overwritten on the source
side; its original lower constructors, release and allocation services remain.
This is source-assisted authoring with native disassembly/comparison, not blind
binary recovery. The pinned source archive and upstream notices are documented
in the [path experiment](../jq-path-network/README.md#original-and-licensing).

Read [BOUNDARY.md](BOUNDARY.md) in the component workspace before editing.
It records byte/codepoint indexing, inputs, shared contents, alias/lifetime rules,
service outcomes, allocation ordering and assumptions. `string-view.h` holds the
actual borrowed buffer; it does not reconstruct a heap from a pointer value.

## Reproduce

Enter `nix develop .#lifting`. Obtain the pinned base package as described in the
[path recipe](../jq-path-network/README.md#reproduce), or reuse a retained comparison's
`inputs` directory with those exact original/tool identities. No extraction or proof
pilot rebuild is required. Starting from that base:

```sh
python tests/fixtures/jq-string-slice/prepare.py "$jq_path_base" build/jq-string-packages
python tests/fixtures/jq-array-storage/prepare.py "$jq_path_base" build/jq-string-arrays \
  --descriptor-layout tests/fixtures/jq-array-storage/unpacked-value-layout.h \
  --descriptor-revision unpacked-descriptors-native-arrays-v1
python tests/fixtures/jq-path-network/prepare.py "$jq_path_base" build/jq-string-paths \
  --resource-checks --array-storage-packages build/jq-string-arrays \
  --string-slice-package build/jq-string-packages/string-slice
spaghetti-headless-wayland python tests/fixtures/jq-string-slice/walkthrough.py \
  build/jq-string-packages/string-slice build/jq-string-arrays \
  build/jq-string-paths build/jq-string-workflow
```

All outputs must be fresh directories. The walkthrough uses public component
start/check, dependency selection and experimental candidate build/test commands.
It edits the UTF-8 decoder, checks the affected network, reuses the independent
array getter, diagnoses Unicode and allocation-order defects, replays retained
bad inputs after repair, then assembles and executes the selected configuration.
Every Wine application, boot and server runs inside the headless Wayland desktop.

## Use the failure consumer in the ordinary component workspace

`prepare-failure.py` adds the warm/cold interpreter failure consumer to an existing
local string-slice package. It retains the component's C, interface, services,
resources and assumptions. Supply the matching pinned backend headers from a
[portable jq project](../jq-portable/README.md); no pilot rebuild is needed:

```sh
# In nix develop .#lifting; both paths refer to existing retained inputs.
jq_string_base=/path/to/string-slice-check/inputs
jq_backend_headers=/path/to/source-project/backends/jq/src
python tests/fixtures/jq-string-slice/prepare-failure.py \
  "$jq_string_base" "$jq_backend_headers" build/jq-failure-package
spaghetti-extractor component start jq string-slice \
  --comparison-package build/jq-failure-package/string-slice \
  --output build/jq-failure-work
spaghetti-headless-wayland bash
# Run checks inside this desktop; repeat this command after editing source/slice.c.
spaghetti-extractor component check jq string-slice \
  --comparison-package build/jq-failure-work --history build/jq-failure-checks
```

Use the printed result directory with `component status jq string-slice
--comparison-result RESULT --case program-string-cold`. A failed check prints a
replay command retaining the failing C even after the workspace is repaired.
After a matching check, return just this component to an existing source project:

```sh
spaghetti-extractor candidate export jq --comparison RESULT \
  --output /path/to/source-project/lifted --update-components --component string-slice
```

Then rebuild and run the affected consumer as described in the portable recipe.
The selected test setup belongs in comparison scope; it does not add a new
precondition to the component contract or require rechecking callers. Changing a
real component assumption would require compatibility review.

The ordinary C driver emits a logical view of the one identified cold context
and exact remaining heap observations, so the standard comparator needs no
target-specific normalization. Physical sizes remain available in stderr.
`build/component-jq-failure-workflow-2026-09-24/` records five matching local/real
consumer cases, a local C edit, an early-release defect caught by existing lifetime
instrumentation, retained replay and repair. The edit compiles one source file;
an unchanged check takes 0.482s with no compilation or execution. The same checked
C then exports under the unchanged contract and runs all eight portable failure
cases on x86-64 and AArch64, rebuilding one component and retaining eleven neighbors.
No checker or proof machinery changed for this handoff.

## Observations and limits

Eight local cases contain 312 retained/unique caller contexts, 192 generated calls
from three fixed seeds, and three allocation failures. They cover ASCII, multibyte
Unicode, embedded NUL, malformed/truncated/overlong/surrogate encodings, signed
index extremes, empty ranges and starts beyond available codepoints. They compare
result bytes/errors, retained bytes, reference counts, output aliasing, real
callback delivery and allocation state through cleanup. Direct borrowed reads
have an explicit live-owner premise, not a checked heap/lifetime proof.

The connected selection keeps the existing array storage and four path/value
components and adds this real dependency. The 44-case consumer suite includes
normal interpreter string slicing and failure armed at the interpreter's actual
string-slice entry. The latter uses the registered native handler and `longjmp`,
then actual interpreter teardown. Both sides retain the same output sentinel,
aliases, references and residual allocations. Those residual allocations include
original lost references; the observer does not repair them or claim leak freedom.

The failure-order mutant constructs the exhausted-start result before releasing
the input. All 156 retained ordinary calls still match. On allocation failure,
the retained input has two references instead of one; residual allocation bytes
are 27 instead of 8. The resource allowance remains satisfied, while the separate
behavioral comparison detects the discrepancy. The Unicode mutant also differs
inside the actual interpreter. These demonstrate complementary observations;
they do not establish universal equivalence or strong activation authority.

## Preparation effort and tooling gap

Evidence is retained in `build/jq-string-slice-2026-09-22/`. The recorded agent
interval to the first matching local comparison is 563.422s, excluding initial
repository inspection. It includes analysis, authoring and execution; it is not
a human usability measurement. Prepared edit/assembly costs are recorded separately
in [the performance ledger](../../../docs/performance-and-invalidation.md).

This fresh trial exposed a real tool-internal gap: resource instrumentation
required ownership roles for plain numeric indices as well as the string value.
The shared validator now allows ordinary integer/float values without token roles,
while continuing to require roles for resource-interpreted numbers, records,
pointers and opaque objects. Four focused regressions cover that distinction.
No new proof rule, artifact format or compiler mechanism was introduced. Nevertheless,
the initial operator trial required a toolkit fix; it is not evidence that every
previously unprepared component can already be authored without tool development.

Manual native ABI analysis, allocation-order analysis, observations and consumer
adapters remain the main preparation work. String construction/destruction, object
storage and other services are still native. This selection is a mixed experimental
jq execution, not a standalone portable jq or another-architecture jq run.
