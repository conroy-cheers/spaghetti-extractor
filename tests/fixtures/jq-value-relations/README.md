# jq equality, containment and object merging

Five entries are authored using the existing value accessors, with no private
array/string/object heap-layout copies. The `jv` handle layout remains explicit
for equality shortcuts and representation identity. See [BOUNDARY.md](BOUNDARY.md)
for argument ownership, aliases, invalid values and retained target quirks.

The 59 native cases include recursive values, embedded NUL, multiplicity,
decimal literals, shared object aliases, two different slices of one allocation,
invalid object slots and positive/negative zero. They compare results, retained
values, backing aliases, reference counts and final heap lifetime. Original
public bodies and exclusively owned relation helpers are trapped. Numeric
comparison and value storage remain shared C services.

Within the lifting shell, with a pinned source `project`, retained native
`inputs/` directory and installed `toolkit`:

```sh
python tests/fixtures/jq-value-relations/prepare.py project work toolkit
python tests/fixtures/jq-value-relations/compare.py work/authoring retained work/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq value-relations \
  --comparison-package work/comparison --output work/checked
```

The checked C is independent of whether the old backend bodies have already
been removed. Edit/recheck through `--reuse-comparison` as usual. Export with
`candidate export jq --comparison work/checked --output project/lifted
--update-components --component value-relations --accept-boundary-change
value-relations`, then refresh using this directory's `portable-bindings.json`.
The adapter supplies the five native symbols; shared helpers used by other
backend operations remain available.

See [the continuation report](../../../docs/jq-value-continuation.md) for combined
normal-entry results and remaining jq work. Source eligibility is separate from
formal proof. These are finite native comparisons and partial source-assisted
lifting. The source adaptation retains jq's [license](COPYING).
