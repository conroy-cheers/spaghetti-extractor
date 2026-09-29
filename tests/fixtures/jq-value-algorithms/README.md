# jq value algorithms

This source-assisted module supplies eight entries: comparison, sorted/unsorted
keys, sort/group/unique, membership and path deletion. It uses the existing jq
value, number and allocation services. Private sorting buffers and recursive
deletion stay ordinary C. See [BOUNDARY.md](BOUNDARY.md) for ownership and scope.

The final 85-case native comparison covers stable ordering, nested values,
decimal literals, NaNs, binary strings, deletion errors/slices, retained aliases
and heap cleanup. A sorting-buffer refactor reuses six compiler objects while
compiling one. The original PE bodies and exclusive helpers are trapped; shared
native slice parsing remains available to unmodified get/set consumers.

Normal execution exposed the target comparator's inconsistent NaN ordering.
The shared [sorting runtime](../portable-runtime/windows-sort.c) preserves the
pinned Wine 11.0 CRT's comparison/swap sequence on both portable architectures.
It is an ordinary C library with no jq dependency. Its LGPL-2.1-or-later notice
and [license](../portable-runtime/COPYING.LGPL-2.1) must accompany distribution.
The other authored C derives from jq under [COPYING](COPYING).

Use the lifting shell and an installed toolkit; `project` is an existing pinned
jq source project and `retained` is a native comparison's `inputs/` directory:

```sh
python tests/fixtures/jq-value-algorithms/prepare.py project work toolkit
python tests/fixtures/jq-value-algorithms/compare.py work/authoring retained work/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq value-algorithms \
  --comparison-package work/comparison --output work/checked
```

Edit the ordinary C in the authoring workspace before preparing the comparison,
or in the comparison workspace for a local edit. Recheck with
`--reuse-comparison work/checked --output work/rechecked`. `comparison-result.json`
retains the exact executable dependencies, observations, compiler reuse and costs.

Export into an existing standalone project with `candidate export jq
--comparison work/checked --output project/lifted --update-components --component
value-algorithms --accept-boundary-change value-algorithms`, then run
`tests/fixtures/jq-portable/refresh.py project --bindings
tests/fixtures/jq-value-algorithms/portable-bindings.json`.
Copy `tests/fixtures/portable-runtime/COPYING.LGPL-2.1` to
`project/provenance/COPYING.LGPL-2.1`; retain the upstream source/version notice.
The bindings remove public bodies and now-unused private helpers. Only the eight
declared native entries must exist in the executable. The build recipe separately
checks that every removed definition is absent from the backend.

The current integration and exact evidence are in
[the value continuation report](../../../docs/jq-value-continuation.md).
`comparison-probe.py project build-receipt native-comparison probe-output`
links a direct C API caller with that project's existing objects. It reuses the
14 original comparison observations and checks exact integer results. Add
`--qemu /path/to/qemu-aarch64` for the AArch64 project. This catches platform
`memcmp` result differences that a CLI consumer using only the sign would miss.
Finite comparisons do not establish universal equivalence or full jq recovery.
