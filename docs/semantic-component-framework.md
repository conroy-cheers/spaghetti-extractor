# Semantic Component Framework

## Scope

Semantic components are selected validation and source-organization units over
canonical reconstruction machine IR. A component may represent an inline
expression, a noncontiguous procedure, a stateful subsystem, or an aggregate
of child components.

Discovery proposes a deterministic, overlapping lattice rather than a trusted
partition. It combines singleton, reconstruction-cluster, SCC, direct-call,
external-event, finite-dispatch, object-affinity, straight-line, and epilogue
closures, then Pareto-ranks the alternatives. An operator selects exact
proposal IDs and may rename or refine their interfaces, but cannot silently
edit proposal membership. Neither discovery nor selection authorizes source.

The framework creates editable portable-C workspaces for reviewed
implementation profiles, checks portable source with CBMC, validates the
generated machine adapter, and runs candidate-only integration against the
sanitized machine interpreter. A valid component definition alone still has
no assurance authority.

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

The catalog's logical interface is an operator hint. A separate structured
`stage-b-component-interface-spec-v1` binds parameters, results, objects,
services, adapter-owned effects, and claims to exact machine-IR locations. The
interface checker requires every machine effect to have exactly one logical or
adapter owner. Missing evidence is `incomplete`; contradictory or stale
evidence is `violated` with unit, RVA, JSON pointer, expected value, observed
value, and remediation. Only a self-bound, issue-free
`stage-b-component-interface-refinement-v1` is authoritative for workspace
creation and qualification.

Member-to-member direct calls are closed explicitly. The boundary records the
call target, continuation, owned return, call-push write, return-target read,
and net stack effect. A helper return remains external if the helper is also an
external component entry. Ambiguous return ownership, recursion, and unbounded
call cycles fail closed in the initial profile.

A selected call to another component is closed by a qualified child workspace,
not by treating the call as an arbitrary C helper. The binding identifies the
exact child component, target RVA, callsite units, qualification artifact, and
self-hashed proof contract. Finite scalar contracts retain their specialized
representation, while other total profiles export the same generic checked
contract envelope. A stale payload, mismatched target, incomplete child, or
unmatched call effect fails closed.

The parent workspace also materializes the exact hash-bound child portable
source and links it into standalone regional checks. Generated parent code
calls the child's qualified portable symbol instead of duplicating its logic.
Aggregate promotion omits that nested copy only when the same portable-source
hash is already promoted as an independent child component, preventing both
semantic drift and duplicate native symbols.

Child effects compose into one ordered external trace. Each selected internal
call is replaced at its callsite by the child's already checked transitive
trace; direct imported calls remain in their original order. Regional cases
may execute a declared prefix when later calls are conditionally unreachable,
but they may not reorder, skip an earlier event, invent an identity, or exceed
the declared trace. Candidate-only cases can script one EAX response per event,
which permits both sides of conditional call paths to be checked without
executing or tracing the original binary.

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

## Federated Linked-Library Recognition

Whole-image lifting must distinguish application code from statically linked
dependencies and compiler/linker support without requiring one central archive
of every library version ever shipped. The linked-library pipeline therefore
uses federated, immutable artifact indexes. A run may combine public catalogs,
private organization catalogs, operator-supplied SDK/toolchain media, and
freshly recovered local artifacts in one content-bound lock file.

Artifact indexing is static-only. The current indexer understands GNU/MS COFF
archives and objects, PE images, and the public-symbol/data-record subset of
OMF used by older DOS/Windows toolchains. It records sections, symbols,
relocations, debug identities, function ranges, and relocation-masked byte
fingerprints. Unsupported thin archives, unresolved OMF fixups, and embedded
PE members are explicit `incomplete` blockers. Names and debug records are
proposal metadata, never proof authority.

Matching combines three independent sources:

- operator-reviewed exact ownership ranges for application or known dependency
  objects;
- machine-IR import-thunk classification;
- exact relocation-masked artifact fingerprints aligned to machine-unit
  boundaries.

The resulting `stage-b-linked-island-manifest-v2` is a total, nonoverlapping
partition of the machine IR. Every unit is classified as `application`,
`linked_dependency`, `compiler_linker_support`, `import_thunk`, or `unknown`.
Ambiguous matches and unmatched code remain visible and make the result
`incomplete`; they are not discarded. The matcher never runs the original
binary.

Recognition deliberately does **not** authorize source replacement. A matched
artifact identity answers only where bytes likely came from. Replacement
requires a separately checked machine-to-logical component contract assigned
to the exact island, plus a qualified portable implementation. Component
qualification artifacts export their exact unit membership, contract
descriptor, and portable-source identity. Replacement planning checks all
three bindings; a catalog status string or an unchecked certificate hash is
not authority. The interface catalog is reusable across implementations that
satisfy that same contract; it need not contain every historical library's
source or internal layout. Identity-only assignments stay `incomplete`,
mismatched membership is `violated`, and fallback to canonical machine IR does
not count as idiomatic-C lifting progress.

The phase artifacts are:

1. `stage-b-library-artifact-inputs-v2`: self-bound catalog snapshot and
   artifact declarations.
2. `stage-b-library-artifact-index-v2`: static member, symbol, relocation,
   snapshot, and content/provenance facts. The v1 reader remains available for
   existing catalogs.
3. `stage-b-library-catalog-lock-v1`: exact selected indexes.
4. `stage-b-library-match-evidence-v1`: all exact target/member alternatives.
5. `stage-b-library-hypothesis-set-v1`: jointly inferred artifact, release, or
   family/ABI identities.
6. `stage-b-dynamic-library-requirements-v1`: exact imported identities and
   checked machine-call boundaries.
7. `stage-b-linked-island-review-v1`: operator-reviewed ownership ranges.
8. `stage-b-linked-island-manifest-v2`: total machine-unit classification.
9. `stage-b-interface-contract-catalog-v1`: reusable checked interfaces and
   portable implementations.
10. `stage-b-linked-interface-qualification-v1`: exact island/contract evidence.
11. `stage-b-library-replacement-plan-v1`: qualified replacements plus explicit
   local-lift or machine-IR fallbacks.

Constellation inference does not count each symbol alias as independent
evidence. It collapses aliases for one exact member range, retains all
incompatible family hypotheses, and reports identity at the strongest tier
supported by the bytes: exact artifact, exact release, library family plus
ABI, ambiguous family, or unidentified. Library-family/ABI identity is enough
to propose common interface contracts, but it does not imply common behavior.

Static-library hypotheses and dynamic-library requirements are deliberately
separate. A PE import identifies an external ABI endpoint, not the DLL build
that will be installed at runtime. Where Stage A has emitted its checked
static-machine-import report, the dynamic phase consumes its exact callsite
routes and variadic argument counts. Inspecting import thunks is only a generic
fallback and cannot qualify variadic or nested-callback callsites by itself.

Unknown ownership is split into deterministic non-call CFG components instead
of one binary-wide island. These ownership components do not constrain later
semantic components: a checked replacement may explicitly compose multiple
ownership islands, and one library may own many islands.

The CA Nix implementation is `nix/stage-b-linked-libraries.nix`. Artifact
corpora, indexes, catalog locks, matching, interface qualification, and
replacement planning are separate derivations, so adding a contract does not
rebuild binary extraction and changing one artifact index does not rebuild
unrelated catalogs.

```sh
nix build .#stage-b-openwatcom19-library-artifact-index --no-link
nix build .#stage-b-gnu-hello-linked-islands --no-link
nix build .#stage-b-gnu-hello-library-hypotheses --no-link
nix build .#stage-b-gnu-hello-dynamic-library-requirements --no-link
nix build .#stage-b-gnu-hello-library-replacement-plan --no-link
nix build .#stage-b-jq-linked-islands --no-link
nix build .#stage-b-linked-library-analysis-smoke --no-link
```

The Open Watcom 1.9 fixture establishes that vintage OMF media can be indexed
without pretending unresolved `FIXUPP` records are matchable. GNU Hello and jq
exercise full PE32 machine-IR partitioning against pinned MinGW runtime
archives. Their current manifests remain truthfully `incomplete`: the catalogs
identify useful compiler/runtime islands, while uncatalogued and ambiguous
regions stay explicit for local lifting or additional artifact acquisition.

Linked-island scope is also imported by semantic-component catalogs,
component registries, and whole-application source bindings. Their reports
show progress by ownership kind and reject stale binary/machine-IR bindings.
Crossing an island boundary is allowed only when it is explicit; artifact
identity itself never activates a component.

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
projection and call closure, a checked logical-interface refinement, and
zero-delta candidate-only integration. Only a
`stage-b-component-qualification-v1` artifact may authorize an override.

For finite acyclic scalar components, the workspace can derive the logical
contract directly from canonical machine IR. The generic scalar profile
symbolically composes every path, proves path exhaustion and overlap
consistency over all 32-bit inputs, emits a portable `uint32_t -> uint32_t`
function, checks that source universally with CBMC, and preserves the exact
machine-visible register and flag projection in its generated adapter. Its
static-string specialization additionally verifies finite indirect-control
tables against exact PE bytes and binds every non-null result to an immutable
NUL-terminated image string. A linker symbol may help name an example but has
no authority in either derivation.

An override may be `total` or `guarded_partial`. A guarded override has a
checked activation domain and must decline with `STAGE_B_UNIMPLEMENTED` before
performing any guest-memory write or observable event when that domain is not
satisfied. The interpreter then discards the attempted replacement state and
executes the canonical machine IR. Qualification therefore establishes that
the portable implementation is correct wherever it activates, while the
canonical interpreter preserves executable behavior elsewhere. Guarded units
remain listed as partial and never reduce whole-program lifting residuals.

Semantic-component boundaries are authoritative for integration. A component
may contain more units than the reconstruction cluster that proposed it; the
regional check executes every resolved member through the declared exits.
Observable live memory comes from the checked logical profile. Adapter-owned
temporary stack storage remains fully classified in the interface ledger but
is not mistaken for a portable component output after the machine frame has
been restored.

The activation registry has two independent statuses:

- registry `status: qualified` means every activated override is qualified;
- `whole_program_status` remains `incomplete` while any machine unit is not
  represented by a qualified component.

## Operator Commands

Discovery and selection are proposal-only phases:

```sh
spaghetti-extractor stage-b-discover-components \
  --machine-ir machine-ir-package \
  --reconstruction-plan reconstruction-plan.json \
  --out component-proposals.json
spaghetti-extractor stage-b-select-components \
  --proposals component-proposals.json \
  --selection component-selection.json \
  --out semantic-components.json
```

Every selection is self-bound. Legacy selections use
`exact_proposal_set_v1`, which also binds the complete proposal-set hash.
Reviewed selections should use `stable_membership_v1`: every selected row
binds the proposal ID and its `membership_bindings_sha256`, while retaining the
proposal-set hash as provenance. This lets unrelated ranking and diagnostic
changes reuse the selection without permitting selected machine facts to
drift. Known direct calls across a proposed procedure boundary remain
fail-closed, but discovery attaches exact callee-entry alternatives to each
call blocker.
Alternatives distinguish blocker-free leaves from procedures that require
their own component calls and from genuinely blocked callees. Selection may
discharge an acyclic chain only when every call blocker is covered by one exact
selected callee membership; recursion, unresolved targets, and non-call
blockers remain rejected. This permits procedure-sized lifting without forcing
every caller to absorb its transitive call graph.

Materialization rechecks the current proposal artifact, copies exact unit
membership, and resets refinement to `not_started`. The declaration records
both the selected and current proposal-set hashes plus the active binding
mode. Improving unrelated discovery diagnostics therefore does not stale a
stable reviewed selection, while a change to any selected proposal's bound
membership facts still does.

Create a conservative interface starting point, edit it if desired, and check
the exact projection:

```sh
spaghetti-extractor stage-b-synthesize-component-interface \
  --catalog semantic-component-catalog.json \
  --machine-ir machine-ir-package \
  --component-id static-word-initialization \
  --out static-word-interface.json
spaghetti-extractor stage-b-check-component-interface \
  --catalog semantic-component-catalog.json \
  --machine-ir machine-ir-package \
  --component-id static-word-initialization \
  --interface-spec static-word-interface.json \
  --out static-word-interface-refinement.json
```

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

For a new opaque PE, the reusable static front half is available as
`flake.lib.mkStageBComponentAnalysis`. It creates separate CA derivations for
binary inventory, opaque export, padding augmentation, machine IR,
reconstruction planning, and proposal discovery. The caller supplies only the
original PE and generic environment/indirect-target profiles. Candidate source,
candidate binaries, runtime tests, linker maps, symbols, and Ghidra artifacts
are not inputs. `stage-b-component-analysis-smoke` exercises this graph on a
small independent PE so jq is not the only integration test.

The editable workflow is:

```sh
spaghetti-extractor stage-b-create-component-workspace \
  --catalog semantic-component-catalog.json \
  --plan reconstruction-plan.json \
  --machine-ir machine-ir-package \
  --interpreter-package interpreter-package \
  --interface-refinement static-word-interface-refinement.json \
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
  --interface-refinement static-word-interface-refinement.json \
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
`stage-b-gnu-hello-component-proposals`,
`stage-b-gnu-hello-selected-component-declarations`,
`stage-b-gnu-hello-selected-component-catalog`,
`stage-b-gnu-hello-component-interfaces`,
`stage-b-gnu-hello-component-slices`, and
`stage-b-gnu-hello-regional-interpreter-kernel`.

Interface synthesis/checking is implemented by the standalone
`nix/stage-b-component-interfaces.nix` CA DAG. It consumes only the checked
component catalog, machine IR, optional reviewed interface specifications, and
a narrow interface-tool source closure. Source compilers, interpreters,
component proof profiles, and candidate binaries are not dependencies. The
larger workspace DAG imports this module rather than maintaining a second
interface implementation.

Each phase is a separate content-addressed Nix derivation. Source proofs and
candidate integration run in parallel; qualification and registry assembly
only consume their immutable outputs.

Proof profiles use a stable plugin interface. A profile owns its machine-shape
contract, generated portable C and adapter, regional cases, CBMC harness,
activation domain, and qualification-scope check in an independently sourced
module. The common workspace orchestrator loads that module by profile ID.
Changing one profile therefore invalidates only components using that profile,
components that explicitly depend on them, and aggregate registry or candidate
descendants.

## Incremental Artifact Graph

Interactive lifting does not reparse the full reconstruction corpus for every
source edit. Discovery is one content-addressed static derivation. Interface
checking and slice extraction are realized separately for every selected
component, and each downstream workspace consumes only its compact checked
refinement and hash-bound `stage-b-component-slice-v1` record. A local slice
contains only the selected component, cluster, and required machine units. Its
identity binds the component self-hash rather than mutable global coverage
counts, so adding an unrelated component converges old slice outputs to their
existing CA paths. Immutable generated scaffolds consume those local outputs;
edited portable C is applied in a separate source-overlay derivation. Aggregate
slice and interface bundles remain inspection artifacts, not workspace
dependencies. Global machine-unit coverage is computed once by registry
composition.

Selection materialization, catalog validation, and interface checking also use
separate minimal Python source closures. The
`stage-b-jq-component-granularity-smoke` derivation instantiates the jq graph
with all selected components and with only `option-name-match`, then requires
the qualification derivation identities to be equal. This checks the intended
invalidation rule at Nix evaluation time rather than inferring it from a warm
build.

Regional checks link against a checked, precompiled host interpreter kernel.
Candidate builds use `nix/stage-b-native-object-graph.nix`: static package
manifests produce a deterministic compile graph, one CA derivation compiles
each source unit, and a separate package/link step validates exact coverage.
Changing one component source therefore invalidates its workspace evidence,
the affected override objects, link/composition, and downstream checks. It
does not invalidate unrelated objects or the static extraction graph.

The component discovery, selection, interface, contract, and workspace modules
are also excluded from the Stage A proof-emitter source closure. Component-only
tooling changes cannot invalidate PE extraction or unrelated Lean generators;
the component derivations that explicitly import those modules remain the
authority for their own invalidation.

Public expected-output suites are also sharded one case per CA derivation and
aggregated only after every report is checked against the exact suite,
candidate hash, command policy, and output artifacts. Wine shards always run
through `xvfb-run`; the original binary is never an input to these derivations.

The intended invalidation contract is:

| Change | Recomputed work |
| --- | --- |
| portable component C | source proof, component integration/qualification, affected native objects, link, functional cases |
| one profile implementation | components using that profile, explicit component dependents, registry/candidate descendants |
| add an unrelated selected component | its local slice/interface/workspace/proofs, registry/candidate descendants |
| generated component boundary | component slice/scaffold and its descendants |
| machine IR or reconstruction plan | slices and all dependent lifting artifacts |
| native build implementation | object graph/checkers, objects, link; static extraction remains cached |
| functional runner or one expected case | affected functional shards and aggregate only |

Wall-clock profiling is diagnostic rather than part of CA artifact contents.
Deterministic reports record unit and case counts; measured timings stay in
build logs or explicit local benchmarks so timestamps cannot poison cache
identity.

## jq Frontend Benchmark

The same generic graph has been run over the full jq 1.8.1 PE32 executable.
The executable contains 4,477 machine units and 11,606 instructions, including
258 x87 micro-operations. All 46,336 executable bytes are classified, all
5,631 direct targets resolve, and no semantic issue is `violated`. Static
reachability currently classifies 1,639 units as exact and conservatively keeps
2,838 as potential. Seventy-five indirect exits remain unresolved, so both the
machine IR and proposal set correctly remain `incomplete`.

Discovery emits 9,246 overlapping proposals and covers every exact and
potential unit. Of these, 7,195 are blocker-free. The inventory includes 310
direct-call closures, 107 loop-SCC closures, 189 external-event branch
coarsenings, 1,137 straight-line closures, 2,566 single-entry control closures,
and the mandatory singleton fallback for all 4,477 units. The committed
operator selection validates twenty disjoint application regions spanning
imported comparisons, terminal output, potential
callbacks, token classification, an opaque-value output route, option-value
collection, wide-argument conversion, an x87-backed callback record, and three
validated PE32-header queries, a Windows path scan, atomic runtime state, and
bounded byte/wide string loops. It is materialized by
`stage-b-jq-selected-component-declarations` and checked structurally by
`stage-b-jq-selected-component-catalog`. The independent
`stage-b-jq-component-interfaces` artifact synthesizes and checks exact
machine-facing interfaces for all twenty selections without executing either
binary. Catalog-level implementation status remains `not_started`; interface
artifacts alone make no implementation or assurance claim.

Twenty selected components now exercise the complete editable path:

- RVA `0x1440..0x149f`, `option-name-match`, has a tracked, register-free
  portable C implementation using a four-operation token-cursor service
  interface. Its adapter retains the exact `msvcrt.dll!strcmp` event.
- RVA `0x1932..0x1967`, `option-token-classifier`, short-circuits non-option
  and double-prefix paths and emits the exact `msvcrt.dll!isalpha` event only
  on its predicate path.
- `usage-write-route` and `usage-exit-route` retain exact terminal output and
  process-exit service boundaries.
- `stderr-value-kind-route` forwards one exact four-word opaque value to its
  libjq service.
- `debug-value-prefix` copies an opaque value, retains its exact stream
  callback and `jv_string` service events, and preserves the callback-produced
  stream value across the second call.
- `output-value-release` copies and releases an arbitrary four-word value,
  preserves the external machine response, and follows the exact continuation.
- `output-value-dump` and `output-value-pipeline` retain their exact ordered
  opaque-value dump/release service protocols.
- `option-value-collection` constructs three exact PE-backed strings and an
  opaque collection through seven ordered libjq calls. It is guarded on DF=0;
  the adapter declines before effects and uses the canonical interpreter when
  that precondition is false.
- `wide-argument-conversion-tail` models one indexed wide-argument conversion,
  including all eight stack arguments and the external stdcall cleanup, before
  advancing to the loop or completion continuation.
- RVA `0x52ed..0x5346`, `math-error-callback-dispatch`, lifts an optional
  callback over a two-word and three-FP64 record. Its regional qualification
  replays the checked `fld`, `fxch`, and `fstp` operations from normalized x87
  metadata. Activation is guarded on a non-faulting x87 domain; unsupported
  forms and exceptional states remain fail-closed on the canonical interpreter.
- `pe32-section-count` and `pe32-image-base` share one checked PE32-header
  query profile. Their adapters preserve the original short-circuit memory-read
  order, while their register-free C consumes a parsed header summary.
- `pe32-section-for-address` extends that profile with a portable first-match
  section-table walk and exact stack-spill effects. It is guarded at sixteen
  sections and falls back before writes when the bound is exceeded.
- `windows-path-info-scan` lifts the MinGW DBCS-aware UNC and DOS-drive path
  scanner as a 59-unit component. Its adapter repeats checked import sites by
  occurrence while the manifest compares contracted imports through their
  bound machine ABI; calls without a complete checked ABI binding retain exact
  register-and-flag comparison. Activation is guarded at sixteen path bytes
  and declines before writes or external events outside that domain.
- `invalid-parameter-handler-get` and `invalid-parameter-handler-exchange`
  lift the MinGW runtime's fixed handler slot into portable state accessors.
  The exchange component retains memory-form `xchg` semantics through the
  runtime's checked sequentially consistent atomic-exchange operation; it is
  not lowered to a non-atomic load/store pair or a source-level approximation.
- `bounded-string-length` and `bounded-wide-string-length` lift the complete
  MinGW `strnlen` and `wcsnlen` loops. Each is guarded at sixteen elements,
  declines before effects outside that domain, and is exhaustively replayed
  across 153 zero-position/limit cases. The wide profile binds the exact
  scaled 16-bit read and proves the portable loop for arbitrary 16-bit values
  within the guarded domain.

All twenty CA qualification artifacts report `qualified`, all required evidence
families satisfied, and zero deltas in their candidate-only regional cases. Their
CBMC source proofs cover the declared input domains and service results. Neither
qualification nor case generation executes the original binary. The registry
authorizes 70 total-domain units and 129 guarded units; 4,407 units still require
total replacements, so this is not jq as a whole.

```sh
nix build --no-link .#stage-b-jq-machine-ir-interpreter
nix build --no-link .#stage-b-jq-component-registry
```

This benchmark is explicitly scoped to `jq.exe`. That PE imports
`libjq-1.dll` and `libonig-5.dll`; those libraries are external services for
the frontend component graph. A source project that links the exact pinned
DLLs may claim only a reimplemented frontend. A complete jq-plus-libraries
reimplementation must analyze and lift each DLL as its own original image and
compose the resulting project scopes. The distinction is represented in the
program ID `jq-pe32-frontend-reference-v1` and must not be inferred from source
provenance or upstream project naming.

On the GNU Hello validation target, the previous serial nine-case Wine run
took about 60 seconds. The sharded cold run completed in about 15 seconds and
an unchanged aggregate rebuild in about 0.06 seconds. Full component workspace
generation previously spent roughly 4.5 seconds and 1.2 GiB parsing the shared
machine IR and plan for each component; reduced slices move that parse to one
static derivation. These figures are indicative local measurements, not
acceptance thresholds.

## Whole-Application Source Projects

Once reviewed components have exposed stable logical interfaces, an operator
may assemble them into an independent source project. This is a separate
artifact layer rather than a qualified component override. The
`stage-b-source-project-spec-v1` declaration records exact reviewed machine
ranges, source islands, entry RVAs, and source symbols. Static binding checks:

- the original binary and machine-IR hashes;
- every source file hash;
- exact machine-unit boundaries for every island;
- nonoverlap between islands;
- complete unit coverage of every reviewed scope range;
- calls, external events, and outgoing control crossing each island boundary.

The reviewed scope is explicit. For GNU Hello it consists of the `.text` and
`.text.startup` ranges contributed by `src/hello.o`; CRT and linked library code
remain out of scope rather than being silently counted as lifted application
logic. A source island outside the scope or one missing scoped units fails
closed.

```sh
spaghetti-extractor stage-b-bind-source-project \
  --machine-ir machine-ir-package \
  --specification source-project.json \
  --source-root idiomatic-source \
  --out source-project-binding.json

spaghetti-extractor stage-b-assess-source-project \
  --binding source-project-binding.json \
  --candidate-binary candidate.exe \
  --functional-report functional-report.json \
  --out source-project-assurance.json
```

Assessment requires the functional report's candidate hash to match the
supplied binary and rejects original runtime observations. A passing report
produces `behavior_validated`, never `pass`: static range binding and public
tests do not prove source semantics. The source-project build, each headless
Wine case, report aggregation, static binding, and assurance are separate CA
derivations. Runtime shards do not depend on machine-IR extraction; only the
static binding and final assurance do.

## GNU Hello Validation Set

The selected validation catalog contains sixteen components. All sixteen
active components have exact entries in the committed selection artifact;
their discovery blockers are either absent or explicitly discharged by a
selected, qualified component-call dependency:

- an inline startup comparison;
- an imported `Sleep` service boundary;
- a locked compare-exchange region;
- callback registration;
- a noncontiguous caller and zero-return helper;
- a checked 36-entry finite dispatch with 12 destinations;
- an alias-sensitive ordered memory update;
- a 25-way short-option classifier;
- a 31-unit in-place range rotation with a checked bounded activation domain;
- an 8-unit byte-string length loop with a checked bounded activation domain,
  an explicit loop invariant and variant, and exhaustive first-NUL path cases;
- a 43-unit Windows error-message lookup derived as a total
  `int32_t -> nullable const char *` function over all input bit patterns;
- a 2-unit ASCII case-conversion helper derived as a total
  `uint32_t -> uint32_t` function over all input bit patterns;
- a bounded ASCII case-insensitive string comparison that composes the checked
  case-conversion helper at two exact callsites;
- a bounded final-path-component lookup;
- a total three-argument imported comparison wrapper expressed as a logical
  zero predicate; and
- a 16-unit program-name selection procedure that composes the comparison
  child, preserves the conditional `strrchr`/`memcmp` trace, and updates its
  checked global output slot.

All sixteen components have qualified implementations. Twelve are total. The
range rotation is guarded to windows of at most six words, the byte-string
length and ASCII comparison components are guarded to sixteen bytes, and the
final-path lookup is guarded to 32 bytes. Their adapters decline before any
write or event outside those domains, after which canonical machine IR handles
the input. The string-loop qualification checks arbitrary byte contents with
CBMC and 153 exact regional cases covering every limit and possible first-NUL
position. The program-name procedure checks ten regional cases spanning its
one- and two-event paths and calls the separately qualified child's portable C
implementation through its checked component contract.
Uncovered entries likewise continue through the content-bound interpreter, so
the hybrid is a complete executable candidate regardless of component
coverage. The separate
`whole_program_status` remains `incomplete`: it measures total portable-C
lifting, not executable coverage. Currently 76 of 7,861 machine units are
totally covered, and 70 additional units have guarded partial coverage.

The GNU Hello discovery artifact currently contains 12,835 overlapping
proposals over 7,861 units and 10,374 graph edges. Every exact and potential
unit appears in at least one proposal. Its overall status remains `incomplete`
because 4,416 localized discovery issues remain visible; that does not
authorize discarding those units. Of those, 4,299 identify proposals with a
known internal call whose callee is outside the proposed membership. Such a
proposal is no longer presented as self-contained: the operator must select a
call-closure alternative or supply a separately checked component-call
contract. The largest per-seed candidate set is five under the configured
limit of twelve.

The candidate-only functional check exercises that composition under a
headless X session:

```sh
nix build --no-link \
  .#stage-b-gnu-hello-component-hybrid-functional-suite
```

The current suite passes all nine curated expected-output cases, covering the
default greeting, help, version, invalid options, traditional mode, short and
long custom greetings, option precedence, and excess operands. These tests are
candidate-only veto evidence. They do not change the incomplete whole-program
portable-source status.

The independent idiomatic-C application project covers all 83 machine units in
the reviewed `src/hello.o` ranges and contains no interpreter or machine-state
runtime. It passes the same nine-case suite. The remaining 7,778 original units
are linked CRT and library implementation, so this establishes complete
declared application-object source coverage, not a whole-image source lift.
Its final source-project artifact reports `behavior_validated` with
`equivalence_status: not_proven`.

The source-call substitution DAG closes the reviewed application's static call
inventory without confusing library names with semantic evidence. It indexes
the exact `libhello.a` used by the original build together with the pinned
MinGW runtime archives, resolves relocation-backed function-pointer slots, and
classifies all 41 calls leaving the three source-bound islands. The current
frontier has 16 dynamic imports, 15 identified static-library calls, four
static internal calls, four indirect calls with finite static target
certificates, and two calls between project islands. No call is dropped because
its library identity is unknown.

The generic proposal phase groups those 41 calls into three exact machine
clusters corresponding to `main`, `hello_parse_options`, and
`hello_print_help`. Clang inventories 31 calls in the idiomatic source; all 31
are covered by those components, including transitive source-local helpers.
The call plan intentionally remains `incomplete`, with exactly one
`source_component_semantics_not_qualified` work item per component. A catalog
may become ready only after checked component evidence replaces each operator
proposal.

The candidate dependency audit is independent of runtime behavior. A trivial
program built by the pinned MinGW toolchain supplies the startup/runtime import
baseline, a reviewed source-runtime closure supplies the additional imports,
and the bound 52-entry envelope is compared with the candidate PE import table.
The current candidate has 52 expected imports and no unexpected imports. The
audit records the candidate, call-plan, and dependency-envelope hashes; it does
not prove source semantics.

```sh
nix build --no-link \
  .#stage-b-gnu-hello-source-call-substitution-smoke \
  .#stage-b-gnu-hello-idiomatic-functional-suite
```

The first derivation is a fast static aggregate. The second runs only the
candidate under `xvfb-run -a wine` and currently passes all nine curated cases.
Closing this reviewed application call frontier is not the same as closing the
whole-image reachability frontier or proving the three source components.

No runtime test of the original binary participates in this workflow. The
candidate-only smoke runs as soon as the machine IR has complete executable-byte
classification and no unresolved direct targets; open indirect frontiers remain
truthfully `incomplete` and may still cause the candidate to fail closed if
reached. Smoke results are veto and repair evidence, never proof authority or a
substitute for whole-program closure. Every Wine invocation uses a headless
Wayland/X session.
