# jq compiler instruction graphs

This source-assisted module supplies the 58 existing construction, binding and
graph-lifecycle operations listed in `native-entries.json`. The independent
bytecode compiler still owns `block_compile`. Ordinary C retains doubly linked
instructions, nested scopes, branch/binding aliases and value/location ownership.
Preparation checks the shared instruction layout against that neighbor.

Read [BOUNDARY.md](BOUNDARY.md) before editing. `ir.c` contains the implementation;
the other C files are ordinary native/portable entry and observation adapters.
Private helpers remain private. The code derives from jq under [COPYING](COPYING).

In the lifting shell, using an existing pinned source project, installed toolkit
and a native comparison's retained `inputs/` directory:

```sh
python tests/fixtures/jq-compiler-ir/prepare.py project work toolkit
python tests/fixtures/jq-compiler-ir/compare.py work/authoring retained work/comparison
spaghetti-headless-wayland spaghetti-extractor component check jq compiler-ir \
  --comparison-package work/comparison --output work/checked
```

Edit the authoring C before preparing a comparison, or the comparison's retained
C for a local check. Use `--reuse-comparison work/checked` with a new output path.
Export with `candidate export jq --comparison work/checked --output project/lifted
--update-components --component compiler-ir --accept-boundary-change compiler-ir`,
then refresh with `tests/fixtures/jq-portable/refresh.py project --bindings
tests/fixtures/jq-compiler-ir/portable-bindings.json`.

The existing backend scanner expects the return type and function name on the
same line. Before the first refresh, change the obsolete `static jv` newline
`make_env(` declaration in `backends/jq/src/compile.c` to `static jv make_env(`.
This is only formatting; the component's replacement list removes that helper.
Removed definitions include obsolete lowering helpers, while declared native
entries are the 58 public operations. The assembly checks those sets separately.

Native adapters preserve general registers because an optimized original caller
keeps ECX live across the leaf `gen_noop`. They use GCC's
[`no_caller_saved_registers`](https://gcc.gnu.org/onlinedocs/gcc/x86-Attributes.html)
with general-register-only code generation. That native glue does not constrain
the platform ABI of exported portable C. A native fault produces a failing
diagnostic instead of waiting in WineDbg.

The [continuation report](../../../docs/jq-ir-continuation.md) records native and
whole-program comparisons, retained discrepancies and remaining scope.
