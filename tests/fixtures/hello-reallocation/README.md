# Complete Hello reallocation through native allocation consumers

`reallocate.c` lifts the complete `rpl_realloc` operation at RVA `[8db8, 8e0f)`.
It normalizes zero to one, rejects requests with the high bit set, calls the raw
allocator, writes errno 12 on failure, and owns its return. The reviewed partition
ends at `8e10`; the intervening byte is unreachable padding. The local oracle
retains nine original transfers and no CRT supplier bodies.

This boundary is an opaque nullable allocation, a full unsigned 32-bit byte
request, a typed resize service and an immediate four-byte errno view. The source
uses generated component types and ordinary C. `bridge.c` supplies synchronous
object/address transport using the existing allocation object definition. An
in-place resize preserves the proxy identity; a moved result has a separate proxy.
The bridge unwraps that result before its stack-scoped context expires.

Raw allocation behavior is an executable assumption, not a checked summary:
failure preserves the old allocation; success preserves the minimum old/new
contents; blocks, errno cells and private stack are disjoint; calls do not deliver
callbacks or mutate unrelated frames. `prepare.py` retains these assumptions and
the exact original/input identities in the existing comparison package.

## Prepare and compare locally

Within the project Python/compiler environment:

```sh
PYTHONPATH=.:src python tests/fixtures/hello-reallocation/prepare.py \
  /path/to/retained-hello/executable-transfer-plan.json \
  targets/gnu-hello/intent/whole-program-partition.json build/hello-reallocation
PYTHONPATH=.:src python -m spaghetti_extractor component check \
  gnu-hello allocation-reallocate \
  --comparison-package build/hello-reallocation/allocation-reallocate \
  --output build/hello-reallocation-local
```

The pinned plan and PE identities are checked before extracting the small slice.
No pilot or toolchain rebuild is required. The 216 cases combine twelve byte
requests, null/live old blocks, in-place/moving/failing allocation and three
deterministic seeds. Requests include zero, prefix boundaries, actual growth sizes,
`INT32_MAX`, `INT32_MAX + 1` and `UINT32_MAX`. Observations include service order,
arguments and returns, immediate errno writes and call-time cells, logical sizes,
allocation lifetime/generation, a 64-byte contents prefix and adjacent frame words.
The original also checks its return stack and preserved registers.

Large allocations are metadata-only locally. Prefix observations and controlled
lifetimes do not establish arbitrary heap contents or actual large allocation.
Scratch-register equality is not part of the source C ABI contract.

## Integrate, edit and replay

Prepare the three [allocation/quoting packages](../hello-allocation-growth/README.md)
and [cleanup package](../hello-quoting-cleanup/README.md), then use the existing
[native walkthrough](../hello-native-quoting/README.md):

```sh
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=.:src spaghetti-headless-wayland \
  python tests/fixtures/hello-native-quoting/walkthrough.py \
  build/hello-components /path/to/retained-pe32-comparison/inputs \
  /path/to/original/hello.exe build/hello-reallocation-native \
  --component-packages --cleanup-package build/hello-cleanup/quote-cleanup \
  --reallocate-package build/hello-reallocation/allocation-reallocate
```

The candidate traps the complete original realloc body and redirects its entry to
selected C. Actual quoting growth calls native `xrealloc`, which calls this entry.
An additional zero-size probe also runs through actual `xrealloc`; direct probes
exercise allocation failure and high-bit rejection. Only those failure probes
replace raw allocation with a controlled failure. Normal growth forwards the
resolved native CRT import. The high-bit probe must make no raw allocator call.
The native observer checks request order/sizes, errno, retained contents, identities
and eventual release; it does not compare physical movement choices between runs.

The five-unit walkthrough checks a compatible realloc edit, recompiles one local
and one integration translation unit, and reuses the unchanged free neighbor.
Changing zero normalization from one to two produces retained local and native
discrepancies. Both replay after the draft is repaired, and the repaired checks
reuse their matching results. Its explicit experimental assembly passes 21 cases.
No new proof rule, solver model, package format or checker is introduced.

The 2026-09-22 checkpoint at
`build/hello-reallocation-2026-09-22/native-workflow-v1/` completes 36 commands and
29 comparisons in 141.578s. Local realloc comparison takes 1.408s, a compatible
local edit 1.593s and native integration 9.633s. Unchanged free reuse takes 0.452s
with no compiler/link/execution/model/solver work. The native run confirms six
selected realloc invocations per case, alongside quoting, growth, free and cleanup.
The existing four-unit walkthrough also passes on the same fixture implementation.
The retained checkpoint audit revalidates 48 comparisons across both walkthroughs,
their experimental assemblies, current code bindings and native counters. Integrated
Nix validation passes 30 tests and six repository/SDK gates. Manual setup remains
substantial: 19 lines of authored C need 63 lines of bridge/header, 118 of controlled
driver and 115 of declaration/preparation Python, plus native fixture extensions.

Higher allocation wrappers still share the native `check_nonnull` tail. Their
text ranges alone would not own their returns; this example makes no replacement
claim for them or their fatal allocation path. The native quoting engine, malloc,
CRT, process startup/TLS, arbitrary callbacks and concurrency remain outside this
scope. Finite matching observations grant experimental execution only, not strong
qualification, complete Hello equivalence or another-architecture coverage.
