# jq numeric values through the public component workflow

`numbers.c` is a source-assisted, ordinary C implementation of eleven existing
numeric entries. `BOUNDARY.md` describes ownership, representation and shared
runtime dependencies. The comparison includes exact double bits, decimal text,
cache identity, reference counts, releases and real interpreter consumers.

Run in the retained lifting environment, using the installed toolkit:

```sh
number_tool="$PWD/build/component-assembly-update-2026-09-27/toolkit-final/bin/spaghetti-extractor"
python tests/fixtures/jq-numbers/prepare.py \
  build/jq-builtin-lifting-2026-09-27/program build/my-numbers "$number_tool"
python tests/fixtures/jq-numbers/compare.py \
  build/my-numbers/authoring \
  build/jq-ir-lifting-2026-09-27/lifecycle/final/inputs \
  build/my-numbers/comparison
spaghetti-headless-wayland "$number_tool" component check jq number-values \
  --comparison-package build/my-numbers/comparison --output build/my-numbers/checked
```

Edit `authoring/source/numbers.c`, prepare another comparison package in a fresh
directory, then check with `--reuse-comparison build/my-numbers/checked`. Native
runtime adapters retain the pinned DLL identity and private service addresses.
The x87 adapter is separate from the portable implementation. Decimal runtime
state is shared with neighboring native code; it is not reconstructed or cloned.
Large decimal outputs are observed as exact byte strings, avoiding conversion
through the harness's JSON number parser.

Apply the matching component to a copy of the existing source project:

```sh
"$number_tool" candidate apply jq --project build/my-jq \
  --comparison build/my-numbers/checked --component number-values \
  --accept-boundary-change number-values \
  --assembly-command "python $PWD/tests/fixtures/jq-portable/refresh.py {project} --bindings $PWD/tests/fixtures/jq-numbers/portable-bindings.json" \
  --check-command 'make -j2 jq live-values'
```

Use the existing portable build/run recipes for full normal-entry comparisons.
The retained `build/jq-number-lifting-2026-09-27/apply.py` supplies both commands
and the expanded case file for x86-64 and AArch64. It integrates through the same
`candidate apply` command; no numeric-specific tooling path exists.

The retained result matches 53 native scenarios and 215 CLI plus 32 live-value
cases on each architecture. All 36 prior component records and exported files
remain unchanged. See [the continuation report](../../../docs/jq-number-continuation.md).
