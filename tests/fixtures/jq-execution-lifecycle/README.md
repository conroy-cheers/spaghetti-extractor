# jq execution lifecycle

This source-assisted module supplies 27 existing `jq.h` operations for creating,
compiling, starting and destroying jq contexts; registering callbacks; attributes;
and error/halt results, plus the existing internal getpath/path-tracking entry.
`jq_next` remains an independently authored neighbor.
Preparation checks the state/frame layout against its retained source package.
No neighboring implementation is needed for routine edits within that boundary.

Read [BOUNDARY.md](BOUNDARY.md) for ownership and callback conventions.
`lifecycle.c` and `execution-stack.h` implement the behavior in ordinary C;
entry adapters preserve the existing production API. Code derives from jq under
[COPYING](COPYING). Use the installed toolkit and lifting shell:

```sh
python tests/fixtures/jq-execution-lifecycle/prepare.py project work toolkit
python tests/fixtures/jq-execution-lifecycle/compare.py work/authoring retained work/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq execution-lifecycle \
  --comparison-package work/comparison --output work/checked
```

`retained` is a prior native comparison's `inputs/` directory. Recheck edited C
with `--reuse-comparison work/checked` and a fresh output path. The driver compiles
and executes real programs in two states, checks registered callbacks and owned
attributes, abandons live results before recompiling, recovers from compilation
errors and checks nulling/repeated teardown and final allocation lifetime.

Export with `candidate export jq --comparison work/checked --output project/lifted
--update-components --component execution-lifecycle --accept-boundary-change
execution-lifecycle`, then refresh with `tests/fixtures/jq-portable/refresh.py
project --bindings tests/fixtures/jq-execution-lifecycle/portable-bindings.json`.
Before the first refresh, join the return type and name of `_jq_path_append`,
`args2obj`, `jq_halt` and `jq_halted` onto one line in the obsolete
`backends/jq/src/execute.c` definitions for the existing definition scanner.

The comparison's native adapters preserve general registers across optimized
native callers. Production entries use the ordinary platform ABI. Native faults
fail immediately. All Wine commands must use a headless Wayland desktop.
The [continuation report](../../../docs/jq-ir-continuation.md) describes evidence
and remaining partial-jq scope; these comparisons do not grant formal authority.
