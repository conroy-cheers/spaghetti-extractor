# Complete Hello cache cleanup through native quoting consumers

`cleanup.c` lifts `quotearg_free`, RVA `[52f2, 5374)`, into ordinary component C.
This is the actual cache cleanup operation, including its loop, all three release
sites, state reset and zero return. The local oracle retains all thirteen original
transfers and excludes the release supplier's body. Existing authoring, comparison,
dependency selection and experimental assembly APIs supply the workflow; no new
proof rule or solver model is needed.

The operation shares `quote-objects.h` with the existing quoting component. Both
components bind the source/header bytes in the existing `hello-quote-cache`
replacement group. Mixed definitions reject even with unchanged C signatures;
this exact input agreement is not a heap-representation theorem. Its
boundary is the current table/count, immortal initial table/buffer, and two typed
release services for buffers and tables. Table and initial-record aliases are
preserved. Slots 1 through count-1 release first, then slot zero when allocated.
The initial record resets before the dynamic table releases; the global table
pointer changes after that release, and the count resets last. The source keeps
those observable distinctions instead of treating cleanup as an unordered list.

The local release service is a declared, executable assumption: synchronous,
returning, accepts null, consumes a live allocation, preserves errno and leaves
cache globals unchanged. It is not a checked summary. The local package has no
selected release implementation. In the native network, both services call the
already selected errno-preserving free component through its actual PE entry.
The root integration requirement selects cleanup alongside growth and free; its
connected checks cover those implementations together. Changing a supplier body
does not supply new local theorem evidence.

## Local preparation and comparison

Within the project Python/compiler environment, use the retained transfer plan
for the pinned Hello executable and the repository's reviewed partition:

```sh
PYTHONPATH=.:src python tests/fixtures/hello-quoting-cleanup/prepare.py \
  /path/to/retained-hello/executable-transfer-plan.json \
  targets/gnu-hello/intent/whole-program-partition.json build/hello-cleanup
PYTHONPATH=.:src python -m spaghetti_extractor component check \
  gnu-hello quote-cleanup --comparison-package build/hello-cleanup/quote-cleanup \
  --output build/hello-cleanup-local
```

Preparation checks the original/plan identity and complete ownership, retains the
small original slice, then uses the public interface and comparison-package APIs.
It records loading, slice rendering and package preparation separately. No pilot
or compiler bootstrap rebuild is required.

The 224 cases vary count 0..64, static/dynamic tables, static/allocated/null slot
zero, sparse other slots, earlier-record aliases and deterministic buffer bytes.
Each case invokes cleanup twice. Observations include return values, final cache
and initial record, the globals visible at every release, order/arguments, live
allocation flags, buffer contents and fixed adjacent frame words. The original
also checks its caller return and preserved registers. The finite driver supplies
explicit object/address transport; it does not infer a general heap relation.
The native adapter checks the same 64-slot limit. The initial local domain was
only 16 slots while the real consumer reached 24; that trial is retained as an
investigation, not the accepted integration. The corrected suite includes 24 and
64. Replacing the old frozen contract with the wider contract rejects until the
operator explicitly reviews and rebinds the consumer requirement.

## Native integration and editing

Prepare the three packages from the
[allocation/quoting recipe](../hello-allocation-growth/README.md), then extend the
[native walkthrough](../hello-native-quoting/README.md):

```sh
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=.:src spaghetti-headless-wayland \
  python tests/fixtures/hello-native-quoting/walkthrough.py \
  build/hello-components /path/to/retained-pe32-comparison/inputs \
  /path/to/original/hello.exe build/hello-cleanup-native \
  --component-packages --cleanup-package build/hello-cleanup/quote-cleanup
```

The original cleanup body is trapped on the candidate side, alongside the earlier
three selected bodies. Runtime checks verify that all four C implementations ran
and that cleanup ran twice per case. Actual native callers make 147 quoting calls
across 21 cases, with cleanup and reentry. Actual lower allocation/quoting/CRT
services remain native. The selected cleanup operates directly on their live
objects through the existing representation adapter.

The 25-command recipe compares local and connected implementations, edits cleanup
compatibly, reuses the unchanged growth neighbor, and deliberately changes the
reset capacity from 256 to 255. The local check catches the value visible at table
release; the native consumer catches the wrong capacity after reentry. It replays
both retained failures after repairing the draft, reuses repaired results, and
builds/runs the four-unit experimental selection. Phase costs and commands remain
in the output directory. Formal checks are not requested.

The 2026-09-22 run at `build/hello-cleanup-2026-09-22/native-workflow-v3/` completes
the whole recipe in 115.518s. Initial local comparison is 1.529s, a compatible
local edit 1.896s and native integration 10.874s. Each edit compiles one translation
unit; unchanged growth and repaired local/native results do no compiler, link,
execution, model or solver work. These are development measurements.
The retained `contract-refinement-rejection/` and `representation-rejection/`
checks reject changed assumptions and mixed shared definitions before compilation.
Neither a stable function signature nor fresh dependency binding bypasses those
checks. `packages-v4/` supplies the final reviewed boundary.

This scope excludes arbitrary shared heap graphs, double-free inputs, callbacks,
concurrency, original startup/TLS and native allocation exhaustion. The original
loop uses signed count comparisons; the admitted local counts are nonnegative and
bounded. Finite observation of this scope grants experimental execution only,
not strong qualification, whole-Hello equivalence or another-architecture coverage.
