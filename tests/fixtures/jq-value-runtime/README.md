# jq shared value runtime through the public workflow

`value-runtime.c` and `slice.c` contain ordinary C for 41 existing production entries. The module
groups related storage operations without absorbing neighboring array, numeric
or object-lifecycle components. See `BOUNDARY.md` for consumption, borrowing,
copy-on-write, hash caches, shared services and assumptions. This is source-assisted
from pinned jq 1.8.1 under COPYING.

In the retained lifting environment:

```sh
value_tool="$PWD/build/component-assembly-update-2026-09-27/toolkit-final/bin/spaghetti-extractor"
python tests/fixtures/jq-value-runtime/prepare.py \
  build/jq-number-lifting-2026-09-27/program build/my-values "$value_tool"
python tests/fixtures/jq-value-runtime/compare.py \
  build/my-values/authoring \
  build/jq-ir-lifting-2026-09-27/lifecycle/final/inputs \
  build/my-values/comparison
spaghetti-headless-wayland "$value_tool" component check jq value-runtime \
  --comparison-package build/my-values/comparison --output build/my-values/checked
```

Local implementation edits use the same preparer with a fresh output directory,
then `--reuse-comparison build/my-values/checked`. The workspace carries the C,
interfaces, dependency headers and assumptions. Changing the harness's argument
encoding establishes a new baseline; it must not claim reuse of a differently
encoded corpus. Native symbol boundaries retain every code address, including
duplicate local symbol names. Unicode arguments are hex encoded, and the long
format case reconstructs the same 2,500 bytes from a compact repeat descriptor.

Apply the checked component to an existing copied source project:

```sh
"$value_tool" candidate apply jq --project build/my-jq \
  --comparison build/my-values/checked --component value-runtime \
  --accept-boundary-change value-runtime \
  --assembly-command "python $PWD/tests/fixtures/jq-portable/refresh.py {project} --bindings $PWD/tests/fixtures/jq-value-runtime/portable-bindings.json" \
  --check-command 'make -j2 jq live-values'
```

`portable-bindings.json` supplies the public hash entry and an accessor to the
existing shared seed. Use `portable-bindings-existing-hash.json` when the project
already provides both through its reviewed hash component/runtime. That variant
retains the existing public provider; the remaining entries use this module.
Both variants share `portable-entries.h`, with ordinary C wrappers for va_list
transport. This is an explicit provider choice, not compatibility inferred from
matching names. The seed, cache layout and lifecycle remain shared.

The retained ARM project also lacked the already available `string-indexes`
component. `build/jq-value-runtime-lifting-2026-09-27/apply-indexes.py` applies its
existing comparison using the standard recipe, while retaining the hash neighbor.
The retained `apply.py` supplies the full build and normal-entry run checks.

The extended module matches 48 native scenarios, with the original recursive
release dispatcher disabled. The existing array-storage boundary keeps public
`jv_free`; this module supplies its guarded non-array `backend_free` service.
Apply this reviewed boundary refinement with the same command above.

The original [value-runtime continuation](../../../docs/jq-value-runtime-continuation.md)
retains its earlier evidence. The current
[runtime-boundary continuation](../../../docs/jq-runtime-boundary-continuation.md)
integrates this refinement with program support: both standalone architectures
match 287 CLI and 32 live-value cases while reusing every neighboring component.

The slice-range refinement adds the private `parse_slice` operation without
changing the path get/set boundaries. Direct comparison checks fractional,
negative, NaN/infinite and null bounds, live aliases, error outputs and aliased
output pointers. When this provider is selected, the jq recipe replaces the old
`native-slice.c` body with a transport-only call to the selected entry.
