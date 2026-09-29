# Hello allocation growth through its quoting consumer

This checkpoint replaces the quoting experiment's simulated `xpalloc` decisions
with the complete operation at RVA `63ac`, authored in ordinary restricted C. The
original executes all 25 retained transfers, including its own return. Its two
lower services, `xrealloc` and `xalloc_die`, remain controlled adapters. The connected
experiment executes the actual quoting, growth and errno-preserving free bodies
against three independently authored components. It is experimental retained-C
evidence; native admission, complete quoting-engine behavior and a portable Hello
executable remain outstanding.

The [native consumer follow-up](../hello-native-quoting/README.md) reuses these
three C units with actual PE32 callers, quoting engine, allocator and cleanup.
It supplies a separate native routine comparison and public experimental workflow;
the controlled failure and transport assumptions of this local suite remain local.

The important boundary is a nullable allocation identity, a live mutable count
cell, positive PE32 additional-count/element-size values, and a signed maximum
represented as explicit 32-bit bits. The C body uses defined wider arithmetic,
retains the target's 64-byte minimum and preserves count publication before a
nonreturning allocator failure. It also preserves the original's small-allocation
limit quirk. Fixing that quirk would change the original behavior.

`declarations.py` defines the boundary and typed services; `grow.c` is the authored
implementation. `bridge.c` and `runtime.h` transport a count and opaque block
identity to reusable allocator callbacks. The identity does not reconstruct heap
contents: the standalone allocator explicitly preserves a sampled prefix and
tracks extent/lifetime; the quoting adapter separately transports and observes
all represented table bytes and aliases. The bridge admits synchronous,
nonreentrant calls. Its failure service carries the published count as an adapter
observation; the actual `xalloc_die` machine call has no argument.

The standalone suite has 522 deterministic edge/generated cases: null/live input,
in-place/moving resize, allocator failure, 50-percent growth, minimum allocation,
maximum behavior and signed-32 count/byte overflow. Large blocks use metadata and
a 64-byte prefix, with unobserved contents disclosed. The connected suite has 144
sequences and exercises initial growth, a second real growth, live relocation,
shared buffers, changing errno cells/options and early/late failures. Its finite
arena is sixteen slots, four table identities and twenty-four buffers. The free
neighbor also has a standalone 32-case check, enabling local admission for each
selected unit instead of a non-executable selection placeholder.

Use retained inputs; no pilot or compiler bootstrap rebuild is needed. Within the
project Python/compiler environment, materialize the original operation once:

```sh
PYTHONPATH=.:src python tests/fixtures/hello-allocation-growth/retain.py \
  /path/to/retained-hello/executable-transfer-plan.json \
  targets/gnu-hello/intent/whole-program-partition.json build/hello-growth-original
```

The recipe rejects a different executable/plan. It uses the existing exact-C slice
API and retains ownership, hashes, callee absence and separate load/render costs.
The quoting input is the retained `quoting-slots` directory from the
[complete quoting walkthrough](../hello-quoting-state/slots/README.md), containing
only the original `exact` and `rpl-free-exact` slices. The free wrapper's C and
manual declaration now live in `preserve-errno-free.c` and
`release_declarations.py`; their source and contract identity are unchanged from
the earlier retained authoring. Neither its old `rpl-free-authoring` directory nor
any completed comparison is needed to prepare this network.

To prepare fresh interfaces, source packages, headers, adapters and dependency
bindings without first running a workflow:

```sh
PYTHONPATH=.:src python tests/fixtures/hello-allocation-growth/network.py \
  /path/to/retained-quoting-slices /path/to/retained-growth/exact \
  build/hello-components
```

The existing APIs construct the declared boundaries and freeze supplier contracts.
The original slices are still required and checked; no original algorithm is
replaced with the authored source on the oracle side. The resulting packages can
be opened with `component start`, checked locally, or supplied to the native
walkthrough using `--component-packages`.

```sh
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=.:src python tests/fixtures/hello-allocation-growth/walkthrough.py \
  build/hello-quoting-state-2026-09-21/quoting-slots \
  build/hello-growth-original/exact build/hello-growth-workflow
```

The script uses public `component start/check` and `candidate build/test` commands.
It edits the growth body compatibly, rechecks local and connected behavior,
reuses the unaffected free comparison, introduces an incorrect count publication,
replays both local and consumer discrepancies, repairs with reuse, and runs the
three-unit experimental assembly. The consumer failure has equal return values
and failure classes; state at the allocator interaction exposes the difference.
Commands, exact retained inputs, observations, separate phase costs and compiler
reuse are under the output directory. Formal checks are not requested.

Two shared facility gaps exposed by this consumer are addressed without a new
proof rule. `nullable_parameters`/`nullable_result` in the existing authoring API
bind optional opaque values and preserve those declarations in consumer schemas.
An uninstrumented parent can legitimately exit before invoking any selected
supplier: a completed observed handler permits this case with zero service
coverage and an explicit unobserved-behavior note. Missing traces, unbalanced
handlers/calls and a root catalog without a service scope remain incomplete.
Eighteen connected cases exercise this early-exit path; they are not discarded
or padded with fictitious supplier calls.

The earlier controlled-growth fixture remains available through its default
`growth-config.h`. This network selects the real operation explicitly. No strong
qualification, native dispatch/link authority or second-architecture execution
is granted by these finite results.
