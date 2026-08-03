# GNU Hello High-Assurance Vertical Slice

## Result

The GNU Hello vertical slice validates the assurance-first reconstruction
workflow on a complete PE32 program. As of 2026-08-02, the static pipeline:

- is generated from a canonical machine IR extracted statically from the
  original PE;
- covers all 79,476 executable bytes selected by the profile;
- lowers all 7,861 selected semantic units;
- recovers 3 of 95 indirect exits as exact finite jump tables;
- derives 1,465 exactly reachable units from four checked roots;
- retains the other 6,396 units as potentially reachable because 47 rooted
  indirect frontiers remain unresolved;
- qualifies seven portable-C regional replacements spanning branch, imported
  call, internal call, atomic, callback, finite dispatch, and alias-sensitive
  typed-memory behavior;
- never executes or traces the original binary.

The lifting evidence is `usable-incomplete`. It is not `qualified`, `pass`,
`conditional_pass`, or a whole-program equivalence theorem. Runtime tests are
therefore not an acceptance signal for the current artifact.

The later whole-application source slice adds an independent idiomatic C
candidate. Its reviewed scope consists of both code ranges contributed by
`src/hello.o`: `.text` at `0x1440..0x1720` and `.text.startup` at
`0x14548..0x14628`. All 83 machine-IR units in that scope are bound to three
source islands, with zero scoped units remaining. The other 7,778 units are
explicitly classified as out-of-scope linked runtime and library code.

That source-only candidate passes all eleven GNU Hello expected-output cases,
covering every script in the upstream 2.12.3 suite, under `xvfb-run -a wine`,
with no original runtime observations. Its
assurance artifact reports `behavior_validated` and `not_proven`; this is strong
candidate-only reconstruction evidence, not a whole-program equivalence claim.

The semantic-component validation layer additionally defines one aggregate
and nine representative leaf components. Their exact membership and machine
boundaries validate successfully, but all nine machine-to-logical refinements
remain `not_started`. The catalog covers 43 units: 39 exact-reachable and four
potential. It leaves 1,426 exact-reachable and 6,392 potential units explicitly
unassigned, so it does not inflate source-lifting progress.

## Reproduce

Build the static lifting evidence and reconstruction plan:

```sh
nix build --no-link .#stage-b-gnu-hello-lifting-evidence
nix build --no-link .#stage-b-gnu-hello-reconstruction-plan
nix build --no-link .#stage-b-gnu-hello-semantic-components
```

Build and validate the representative hard workspaces:

```sh
nix build --no-link .#stage-b-gnu-hello-dispatch-workspace-check
nix build --no-link .#stage-b-gnu-hello-typed-memory-workspace-check
nix build --no-link .#stage-b-gnu-hello-atomic-workspace-check
nix build --no-link .#stage-b-gnu-hello-callback-workspace-check
nix build --no-link .#stage-b-gnu-hello-reconstruction-registry
```

Build the independent application source project:

```sh
nix build --no-link .#stage-b-gnu-hello-idiomatic-source-binding
nix build --no-link .#stage-b-gnu-hello-idiomatic-candidate
nix build --no-link .#stage-b-gnu-hello-idiomatic-functional-suite
nix build --no-link .#stage-b-gnu-hello-idiomatic-upstream-suite
nix build --no-link .#stage-b-gnu-hello-idiomatic-assurance
```

Each workspace is content addressed and its generated skeleton must compile.
All seven portable implementations are promoted only after candidate-only
validation succeeds. Five belong to the exact rooted closure; dispatch and
typed memory remain potential-reachability examples and therefore do not
inflate exact rooted lifting progress.
Wine remains gated on complete static closure; when used, it runs through a
headless Wayland/X session and compares only against curated expected outputs.

## Artifact Bindings

The current static artifact binds:

- original PE SHA-256:
  `71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c`;
- every machine-IR unit to its exact original RVA, byte hash, and source
  semantic-transfer contract;
- every external call annotation to the selected profile id, entry, and
  profile hash;
- every reconstruction plan and workspace to the machine-IR content hash.

Nix CA derivations separate the original extraction, machine IR, interpreter,
native engine, native runtime, regional harness kernel, C replacement,
candidate, regional validation, runtime suite, and assurance aggregation. An
unchanged build substitutes all outputs. A regional source edit retains the
large machine-IR and harness products and invalidates the replacement's
dependent closure.

## Regional Replacement

The first replacement is deliberately small but real. It replaces the
generated transition for the entry-initialization region with independently
compiled C that writes zero to guest address `0x00430348` and continues at RVA
`0x1010`.

A candidate-only harness executes the generated baseline transition and the C
replacement from identical machine and memory states. It compares control,
register outputs, memory views, faults, and external events through the generic
regional contract format.

A deterministic mutation changes the written byte from `00` to `01`. The
validator returns `violated` and identifies:

- cluster `cluster:gnu-hello-entry-initialization`;
- original RVA span `0x1420..0x142f`;
- `gnu-hello-entry-replacement.c`, line 8;
- JSON path `/memory_views/memory:startup-global/after/0`;
- expected byte `00`, observed byte `01`.

This establishes that the replacement loop gives source-localized repair
feedback and catches a concrete semantic defect. It does not establish that
one test state exhausts the region's input domain. Larger replacements must
add solver, exhaustive, or generated differential cases appropriate to their
live inputs.

## Evidence And Assumptions

The reports preserve evidence classes rather than treating all closure as a
proof. Finite inventories are `exhaustive`; regional comparison and mutation
results are `differential`; public behavior cases and timing are `integration`.
The 47 rooted indirect frontiers are explicit blockers; a global profile may
not turn them into finite target sets. The following dependencies remain
explicitly `assumed` for already reconstructed regions:

1. The pinned PE frontend, decoder, and machine-IR normalizer are correct for
   the 6,516 distinct concrete normalized instruction forms in this binary.
2. The generated IR-to-C state-machine lowering and runtime are correct.
3. The external profiles and native API/callback bridges implement their
   declared machine-level contracts.
4. Equal ordered external calls with related arguments receive related results
   and effects.
5. The pinned C compiler, assembler, linker, and PE composer preserve the
   generated source semantics.

The 6,516 count is a concrete operand-bearing form inventory, not 6,516
independently proved opcode families. Bochs, Unicorn, hardware vectors, Lean,
and strict corpora can reduce the first assumption incrementally, but the
current report does not claim that work is complete.

## Viability Assessment

This slice supports the pivot's core premise:

- an opaque binary can be statically converted into a complete executable
  machine-state source baseline;
- candidate runtime behavior can be checked without observing the original;
- a small region can be rewritten as ordinary C and validated independently;
- a bad rewrite produces localized feedback;
- Nix keeps unrelated extraction and generation work reusable.

The follow-up lifting slice covers three additional semantic classes:

- RVA `0x1038`: a comparison/equality branch becomes a pure `compare_values`
  helper; a generated adapter reconstructs the exact x86 flags and two exits.
- RVA `0x1040`: `kernel32.dll!Sleep` becomes a typed service method taking
  milliseconds; the adapter preserves the import identity, argument, stack
  write, response state, and continuation.
- RVA `0x1201` plus callee RVA `0xa290`: static-word initialization and the
  zero-return helper become a typed result transformation; the adapter owns
  guest-memory effects and machine outputs.

Their candidate-only checks compare 4, 2, and 2 generated cases respectively,
with no deltas. The content-addressed registry promotes all three independently
validated workspaces. A branch-predicate mutation returns `violated` and adds
the exact edited line in `src/implementation.c` to the repair locations.

The improved plan discovers 4,573 disjoint cutpoint-bounded clusters from the
7,861 machine-IR units. Twenty-eight clusters match a reviewed portable
template. The others receive a compilable manual-contract skeleton rather than
speculative semantics.

Four real regions exercise the new generic evidence and portable-C adapters:

- RVA `0x382f`: a path-bound 36-entry jump table with 12 distinct targets;
  all 36 exhaustive selector cases qualify with no deltas.
- RVA `0xd0e9`: neighboring regions produce stack and object views, including
  object fields at offsets `+4` and `+8`; 73 boundary cases and 28 executable
  exact/partial-alias cases qualify with no deltas. Multi-unit composition
  records prior writes on later loads instead of silently resetting memory at
  a cutpoint.
- RVA `0x1050`: `lock cmpxchg` is retained as one atomic compare-exchange
  effect with the concrete read/write pair and x86 locked ordering; 13 success
  and failure cases qualify with no deltas. The concrete harness is
  single-threaded, so locked concurrency semantics remain an explicit runtime
  contract rather than a tested claim.
- RVA `0x1137`: `SetUnhandledExceptionFilter` is a typed callback-registration
  service with an exact callback target, lifetime, ABI, nested frame, result
  relation, and an additional rooted callback entry; both generated cases
  qualify with no deltas.

The registry therefore contains seven qualified replacements. Its status
remains `incomplete`: 922 exact-reachable clusters exist, five are promoted,
917 remain, 901 of those have no reviewed portable template, and 47 rooted
indirect frontiers still prevent closed whole-program reachability.

This validates the lifting workbench, contract precision, and conservative
coverage policy. It does not imply that GNU Hello has been fully lifted into
idiomatic C or that its whole-program static frontier is closed.
