# Semantic Component Framework

## Scope

Semantic components are operator-defined validation and source-organization
units over canonical reconstruction machine IR. A component may represent an
inline expression, a noncontiguous procedure, a stateful subsystem, or an
aggregate of child components.

The framework does not infer components or minimize their boundaries. It now
creates editable portable-C workspaces for reviewed implementation profiles,
checks the portable source with CBMC, validates the generated machine adapter,
and runs candidate-only integration against the sanitized machine interpreter.
A valid component definition alone still has no assurance authority.

## Two Boundaries

The machine boundary is derived from the content-bound machine IR and
reconstruction plan. It records:

- exact member unit identities and RVA spans;
- roots and incoming control from outside the component;
- direct, return, and indirect exits;
- checked finite indirect-target inventories;
- register, flag, memory, external-event, and fault effects;
- exact, potential, or mixed rooted reachability.

The initial state relation is the conservative full machine state. Boundary
minimization is explicitly `not_attempted`.

The logical interface is an operator proposal containing parameters, results,
objects, persistent state, services, preconditions, postconditions, and
observations. It remains non-authoritative until a separate refinement step
checks its projection from the machine boundary.

Member-to-member direct calls are closed explicitly. The boundary records the
call target, continuation, owned return, call-push write, return-target read,
and net stack effect. A helper return remains external if the helper is also an
external component entry. Ambiguous return ownership, recursion, and unbounded
call cycles fail closed in the initial profile.

## Hierarchy And Coverage

Components may contain child components. Their resolved membership includes
all descendants. Overlap is accepted only between ancestors and descendants;
incomparable overlap is a violation. A shared child must be declared as such
before it may have multiple parents.

The catalog retains a global residual ledger. It separately reports selected
exact-reachable units, selected potential units, and every unassigned unit in
both classes. `complete` requires both inventories to be assigned, so an open
indirect-control frontier cannot be hidden by completing only the currently
exact closure.

## Statuses

The following claims are independent:

- `definition_status`: membership, hierarchy, binding, and reachability are
  structurally valid;
- `refinement_status`: machine-to-logical or later refinement evidence exists;
- `implementation_status`: an implementation has been supplied;
- `assurance_status`: the selected component and global coverage obligations
  are closed.

Qualification is a separate artifact. It requires current source-level CBMC
evidence, byte-exact regeneration of the machine adapter, checked machine
projection and call closure, and zero-delta candidate-only integration. Only a
`stage-b-component-qualification-v1` artifact may authorize an override.

The activation registry has two independent statuses:

- registry `status: qualified` means every activated override is qualified;
- `whole_program_status` remains `incomplete` while any machine unit is not
  represented by a qualified component.

## Operator Command

```sh
spaghetti-extractor stage-b-validate-components \
  --machine-ir machine-ir-package \
  --reconstruction-plan reconstruction-plan.json \
  --declarations semantic-components.json \
  --out semantic-component-catalog.json
```

The command is static and never executes the original binary. The CA Nix
validation artifact is:

```sh
nix build --no-link .#stage-b-gnu-hello-semantic-components
```

The editable workflow is:

```sh
spaghetti-extractor stage-b-create-component-workspace \
  --catalog semantic-component-catalog.json \
  --plan reconstruction-plan.json \
  --machine-ir machine-ir-package \
  --interpreter-package interpreter-package \
  --component-id static-word-initialization \
  --proof-profile store_then_zero_call_v1 \
  --out-dir work/static-word
# Edit only src/implementation.c.
spaghetti-extractor stage-b-rebind-component-workspace \
  --workspace work/static-word
spaghetti-extractor stage-b-check-component \
  --workspace work/static-word --out work/static-word/source-evidence.json
spaghetti-extractor stage-b-run-replacement-check \
  --workspace work/static-word \
  --interpreter-package interpreter-package \
  --out-dir work/static-word
spaghetti-extractor stage-b-qualify-component \
  --workspace work/static-word \
  --source-evidence work/static-word/source-evidence.json \
  --out work/static-word/component-qualification.json
```

For repeated edits, reduce the static inputs and build the regional kernel
once:

```sh
spaghetti-extractor stage-b-create-component-slices \
  --catalog semantic-component-catalog.json \
  --plan reconstruction-plan.json \
  --machine-ir machine-ir-package \
  --component-id static-word-initialization \
  --out-dir work/component-slices
slice=$(jq -r '.entries[0].path' \
  work/component-slices/component-slice-package.json)
spaghetti-extractor stage-b-build-regional-kernel \
  --interpreter-package interpreter-package \
  --out-dir work/regional-kernel
spaghetti-extractor stage-b-create-component-workspace \
  --component-slice "work/component-slices/$slice" \
  --interpreter-package interpreter-package \
  --component-id static-word-initialization \
  --proof-profile store_then_zero_call_v1 \
  --out-dir work/static-word
spaghetti-extractor stage-b-run-replacement-check \
  --workspace work/static-word \
  --interpreter-package interpreter-package \
  --regional-kernel work/regional-kernel \
  --out-dir work/static-word
```

The corresponding reusable GNU Hello Nix artifacts are
`stage-b-gnu-hello-component-slices` and
`stage-b-gnu-hello-regional-interpreter-kernel`.

Each phase is a separate content-addressed Nix derivation. Source proofs and
candidate integration run in parallel; qualification and registry assembly
only consume their immutable outputs.

## Incremental Artifact Graph

Interactive lifting does not reparse the full reconstruction corpus for every
source edit. A single static reduction emits hash-bound
`stage-b-component-slice-v1` records containing only the selected component,
cluster, and required machine units. Immutable generated scaffolds consume
those slices; edited portable C is applied in a separate source-overlay
derivation. The full catalog, reconstruction plan, and machine IR remain bound
by hash and are re-read only when static inputs change.

Regional checks link against a checked, precompiled host interpreter kernel.
Candidate builds use `nix/stage-b-native-object-graph.nix`: static package
manifests produce a deterministic compile graph, one CA derivation compiles
each source unit, and a separate package/link step validates exact coverage.
Changing one component source therefore invalidates its workspace evidence,
the affected override objects, link/composition, and downstream checks. It
does not invalidate unrelated objects or the static extraction graph.

Public expected-output suites are also sharded one case per CA derivation and
aggregated only after every report is checked against the exact suite,
candidate hash, command policy, and output artifacts. Wine shards always run
through `xvfb-run`; the original binary is never an input to these derivations.

The intended invalidation contract is:

| Change | Recomputed work |
| --- | --- |
| portable component C | source proof, component integration/qualification, affected native objects, link, functional cases |
| generated component boundary | component slice/scaffold and its descendants |
| machine IR or reconstruction plan | slices and all dependent lifting artifacts |
| native build implementation | object graph/checkers, objects, link; static extraction remains cached |
| functional runner or one expected case | affected functional shards and aggregate only |

Wall-clock profiling is diagnostic rather than part of CA artifact contents.
Deterministic reports record unit and case counts; measured timings stay in
build logs or explicit local benchmarks so timestamps cannot poison cache
identity.

On the GNU Hello validation target, the previous serial nine-case Wine run
took about 60 seconds. The sharded cold run completed in about 15 seconds and
an unchanged aggregate rebuild in about 0.06 seconds. Full component workspace
generation previously spent roughly 4.5 seconds and 1.2 GiB parsing the shared
machine IR and plan for each component; reduced slices move that parse to one
static derivation. These figures are indicative local measurements, not
acceptance thresholds.

## GNU Hello Validation Set

The committed declaration contains one aggregate and nine leaf components:

- an inline startup comparison;
- an imported `Sleep` service boundary;
- a locked compare-exchange region;
- callback registration;
- the short-option comparison at RVA `0x11ac`;
- a noncontiguous caller and zero-return helper;
- the 31-unit loop and out-of-line control region at RVA `0x1ba0`;
- a checked 36-entry finite dispatch with 12 destinations;
- an alias-sensitive ordered memory update.

Seven components currently have qualified implementations: comparison,
`Sleep`, atomic compare-exchange, callback registration, static-word
initialization, finite dispatch, and alias-sensitive memory update. The
short-option and rotate components remain unimplemented. Uncovered entries
continue through the content-bound machine-IR interpreter, so the hybrid is a
complete executable candidate regardless of component coverage. The separate
`whole_program_status` remains `incomplete`: it measures portable-C lifting,
not executable coverage. Currently 11 of 7,861 machine units are covered by
qualified components.

The candidate-only functional check exercises that composition under a
headless X session:

```sh
nix build --no-link \
  .#stage-b-gnu-hello-component-hybrid-functional-suite
```

No runtime test of the original binary participates in this workflow. The
candidate-only smoke runs as soon as the machine IR has complete executable-byte
classification and no unresolved direct targets; open indirect frontiers remain
truthfully `incomplete` and may still cause the candidate to fail closed if
reached. Smoke results are veto and repair evidence, never proof authority or a
substitute for whole-program closure. Every Wine invocation uses a headless
Wayland/X session.
