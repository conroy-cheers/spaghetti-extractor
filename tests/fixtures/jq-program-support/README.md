# jq program support through the component workflow

This module lifts 23 existing entries through ordinary, source-assisted C:
UTF-8 scanning/conversion, source-location ownership/diagnostics, and bytecode
metadata, disassembly and destruction, home-path expansion, byte search, lexical
path canonicalization, dirname and basename. It reuses the existing `bytecode.h`,
`locfile.h` and jv layouts. [BOUNDARY.md](BOUNDARY.md) describes the borrowed spans,
shared objects, frames, callbacks and destruction rules.

Use the installed toolkit inside the retained lifting environment. `project` is
an existing portable jq project; `native` is a retained native comparison's
`inputs/` directory. Choose fresh output directories:

```sh
python tests/fixtures/jq-program-support/prepare.py "$project" "$work/support" "$toolkit"
python tests/fixtures/jq-program-support/compare.py "$work/support/authoring" "$native" "$work/comparison"
spaghetti-headless-wayland "$toolkit" component check jq program-support \
  --comparison-package "$work/comparison" --output "$work/checked"
```

The 104 native scenarios include all 256 leading-byte classifications, invalid
and truncated UTF-8, unchanged input/output frames, scalar boundaries, retained
source-file aliases and exact diagnostic messages. Ten real compiler scenarios
each use two jq contexts, snapshot bytecode/parent/global relationships, compare
exact disassembly bytes, execute filters and tear down the compiled graphs.
Home cases compare environment precedence, error messages and retained path
aliases. Byte-search cases observe interior offsets, empty inputs and aliased
buffers. Path cases observe nonexistent names, roots/drives, dot segments,
capacity failure, two current-directory contexts, borrowed aliases and unchanged
input frames. All 23 native entries are exercised directly, and their original bodies and
selected private helpers are disabled on the source side. Allocation observations
use the existing shared fixture. They are practical evidence, not a formal proof.

The portable C preserves original edge behavior, including single-byte
backtracking and surrogate encoding. Two pointer expressions are rewritten to
avoid forming out-of-range pointers while keeping the observed native results.
Formatting transports a live `va_list`; no synthetic production API is required.
Native ABI glue stays outside the authored implementation.

Integrate with the same apply operation used for local edits:

```sh
"$toolkit" candidate apply jq --project "$project" --comparison "$work/checked" \
  --component program-support --accept-boundary-change program-support \
  --assembly-command "python $repo/tests/fixtures/jq-program-support/assemble.py {project} --bindings $repo/tests/fixtures/jq-program-support/portable-bindings.json"
```

Append build and headless program-run `--check-command` arguments to require
validation before publication. The bindings retire the old definitions; normal
project builds reuse neighboring objects. No checker, compiler or engine change
is needed for this boundary or its C.

The current refinement is at `build/jq-path-services-lifting-2026-09-27/`.
`support/final/` contains 104 native matches. Both `host-final-run/`
and `arm-final-run/` contain 324 CLI and 32 live-value matches. The three refined
components preserve all 39/40 neighboring component records and source files.
The shared path library is supplied once here; file input and module search use
the same namespace and classification contract. `assemble.py` retains its library
notices and invokes the existing assembly recipe.
See the [current report](../../../docs/jq-path-services-continuation.md) for
costs, remaining dependencies and evidence paths. The
[original report](../../../docs/jq-program-support-continuation.md) retains the
earlier seventeen-entry experiment.
