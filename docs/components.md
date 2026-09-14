# Composable Component Lifting

An explicitly configured source-edit product can compare ordinary C against a
retained source baseline:

```sh
spaghetti-extractor component check TARGET COMPONENT --source --compare-baseline
```

The target exposes `components.units.COMPONENT.sourceEditCheck` and lists
`sourceEditCheck` in that unit's operator products. Use
`nix/component-source-edit-check.nix` with `interfacePackage`, `sourcePackage`,
`baselineInterfacePackage`, `baselineSourcePackage` and a manual `boundary`:

```nix
boundary = {
  operation_id = "cleanup";
  source = "cleanup.c";
  entry = { position = "after"; text = "  /* exact complete entry line */\n"; };
  exits = {
    next = { position = "before"; text = "  /* exact complete next line */\n"; };
    tail = { position = "before"; text = "  /* exact complete tail line */\n"; };
  };
};
```

Replace the example text with lines already present in both sources. Anchors
must be unique complete lines (or consecutive lines), with at least two named
exits. Proof markers are inserted into copies, then checked to erase back to
both compiled ordinary sources. This defines a proof region within an operation;
it does not add production functions or split replacement ownership.

The current profile permits finite scalar branching and newly introduced private
nonescaping scalar storage. Wider state, service or representation edits report
incomplete. Both host and PE32 source portability checks still run. Optional
`previousSourceEdit` supplies a previous product for exact local-query reuse.
Optional `baselineConditionalPacket` supplies the actual
`conditional-engine-result.json`; the reader checks its source and full
interface identity, including the regenerated logical proof-interface digest,
and preserves its assumptions, obligation statuses, coverage
selection and pending boundary requirements. Missing, stale or unsupported
baseline evidence is reported separately from the source comparison. Logical
projections requiring additional machine-contract context remain unsupported by
this baseline bridge.

A complete source-edit status means the supported source comparison and source
portability checks passed. It does not import the baseline application proof,
complete an unresolved baseline, reuse neighboring application proofs, or
authorize supplier export or activation. This command cannot be combined with
`--conditional` or `--local-contracts`.

To require a checked embedding in a retained application's proof environment,
configure the full engine output and select one compiled baseline obligation:

```nix
baselineConditionalEvidence = previousProvider.engineDerivation;
baselineObligation = "sync:loop";
baselineQueryTransport = true; # Optional: carry completed bounded property checks.
```

This replaces `baselineConditionalPacket`. Preserve the original Nix output's
reference closure: its diagnostic compilation paths still refer to the original
source package and exact-C inputs. Copying the diagnostic tree as an unrelated
flake source can lose those references and must report incomplete.

The checker first reproduces the original GOTO model byte for byte, then checks
both ordinary/marked source pairs and the complete context around the changed
region. The local query must be identical in the ordinary and baseline proof
environments. If this requested embedding is unsupported, local scalar success
alone cannot complete the command. The extra context work is currently material
to latency; see [measurements](performance-and-invalidation.md).

The `baseline_context` result retains the original assurance and obligation
status, model and interface digests, and local-query binding. Without
`baselineQueryTransport`, it supplies only the checked embedding. With that option,
it also reparses published successful property-query processes and checks the
complete CBMC-processed context, including generated assertion predicates,
property IDs and backward-GOTO loop IDs. Unknown query modes report incomplete.
The supported query scope has explicit unwind bounds and disabled unwinding
assertions: transported results remain bounded checks under the original runtime
contracts. Missing, failed, coverage and unfinished application queries acquire
no result through this rule. Limits naming loops absent from both checked models
are retained and identified as inactive.

`query_transport` records the original process binding and output separately
from the edited-model correspondence. It never rewrites a cache key to claim
CBMC ran on the edited model. `previousSourceEdit` may also reuse a processed
context after current validation of its exact four model digests, query policy,
source comparison and retained artifacts. The encompassing application obligation
and pending boundary requirements retain their original statuses. Activation,
strong receipts and neighboring complete-component theorem reuse remain separate.

Explicit conditional checks with no pending boundary requirements also emit `conditional-refinement-result.json`
(`spaghetti-extractor-conditional-contextual-refinement-v1`). It runs the shared
contextual proof validators with a required, exact runtime-contract selection;
its receipt and each model, proof-input and execution layer bind that selection.
The normal `contextual-refinement-v2` reader rejects these conditional records.
Successful auxiliary frames and wider-entry theorems can be checked under the
same explicit selection against retained solver/GOTO bytes. Failed or missing
auxiliary facts do not become guarantees because the main proof passed.

This artifact is a conditional component theorem. The diagnostic engine packet
remains the public feedback and exact-query-reuse input. Neither artifact grants
native activation, and supplier use additionally requires checked source-summary, postcondition
and entry/frame rules. The conditional shared-supplier path now applies those
rules with explicit runtime assumptions and retained solver/GOTO evidence.
`providerComponents.ID.conditionalRefinement` is available only in a conditional
work-package check and is mutually exclusive with ordinary qualification inputs.
All supplier assumptions must occur exactly in the caller's selected contract
set; a revision or semantic-hash change is not accepted as compatibility.
Complete local consequences still reject continuation and allocation-history
premises that have no component-composition discharge. Conditional supplier
loading currently supports the existing checked shared-state leaf contract;
transitive shared-state suppliers remain outside that implemented domain.

The public conditional checker can investigate a binding with authored pending
requirements, provided normalization finds no structural inconsistency. It
retains the exact requirements in the diagnostic packet's input and result,
and displays them separately from local proof obligations. Passing the local
obligations does not discharge those requirements: feedback remains incomplete
and no conditional supplier theorem is emitted. Unknown requirements are never
assumed true. Missing operation authority, inconsistent services and invalid
contracts still stop preparation; the default qualification gate is unchanged.
Completed local queries may be reused under their existing exact model/evidence
rules while requirements are refined. That reuse does not prove the requirements
or establish compatibility of a changed component contract.

Configured products can expose `conditionalCheckFor` alongside `conditionalCheck`
to accept focused requests through the same Nix provider:

```sh
spaghetti-extractor component check TARGET COMPONENT --conditional \
  --region 'cleanup/sync:allocated' --query-timeout 60
```

`--region` is repeatable and names an operation plus an existing obligation ID
from the check details. Unknown or duplicate selections reject before solver
execution. `--query-timeout` controls each query, including subdivision retries;
it is not a deadline for the command. The provider accepts `selectedObligations`
as canonical `{ operation_id, obligation_id }` rows, or its
`conditionalCheckFor { obligations = [...]; queryTimeoutSeconds = 60; }`
function can supply the public product directly.

Focused checks retain the complete prepared model/coverage inventory and compile
only selected regions. Other regions have explicit incomplete scheduling records,
with no compiled-model or execution digest. Feedback reports the selected result
and deferred coverage separately. A focused check always withholds supplier
theorem export, including when all requested queries pass. Completed selected
queries can be reused; deferred regions supply no query evidence. These are proof
regions within the authored component, not new production APIs or independently
liftable components.

Components are the supported unit of candidate reconstruction work. They let an operator replace
one exact machine region, a procedure-sized group, or a larger subsystem while
every other structural unit remains owned by the machine-IR fallback.

The current canonical operator artifact is `component-work-package-v6`, a
non-authorizing content-addressed `semantic-slice-v2` projection from
`linked-semantic-module-v2`.  Its owned definitions are distinct from the
faithful-C context shown to the operator.  Portable authority is
`semantic-provider-qualification-v2`; the direct path runs contextual
refinement, generates the machine overlay, and compiles the PE32 objects from
the V6 package without consuming a component-contract V4, machine-binding V5,
or component-implementation V4 artifact.  Total
`implementation-selection-v2` then explicitly selects that provider or the
generated Behavioral-C provider for every definition.

GNU Hello's `ascii-to-lower` is the first deployed direct vertical.  The
program-name, callback-registration, induction, and reusable-library verticals
exercise the same path. jq and DX-Ball also emit direct V6 work packages, but
their unresolved machine-effect and portable-interface reviews remain explicit
blockers. The public V4 contract/implementation/dependency DAG has been removed.
Some proof-kernel types still carry historical names internally; they are
in-memory implementation details and must not be serialized or exposed as a
second component system.

## Two Graphs

For a draft continuation relation, `continuation_unit_ids` names unowned exact
units retained in `transfer_ids` alongside the owned `unit_ids`. Public review
keeps replacement membership unchanged; canonical proof input generation checks
the referenced context. The bounded common-prefix proof compares both executions
through that exact context. A local proof can pass while provider qualification
remains incomplete: dispatch/link validation must preserve the required context
behavior before activation. Calls without checked context contracts remain
unsupported. An unproved dead-register annotation cannot waive state checks.

The machine-IR graph is canonical. Component boundaries do not alter it. The
authored component catalog is a work graph over exact machine-unit membership.
Alternative groups may overlap, but one selected configuration may not: every
structural unit has exactly one implementation owner.

This is what makes local work possible without a complete understanding of the
target. Selecting one component does not require lifting its callers, callees,
or unrelated regions first.

## Canonical Lifecycle

Artifact version numbers describe individual wire formats, not one global
component generation. New boundary-aware components use
`PortableComponentInterfaceV5`, which references the shared canonical schema,
checked operation projections, and lifecycles. Source package V3 remains the
implementation package. The interface is machine-free; exact machine meaning
lives in the checked binding intent and its content-addressed semantic slice.

The component DAG produces these independently cached artifacts:

1. `v5Interfaces.<id>`: the checked human-facing operation and boundary schema.
2. `bindingIntentPaths.<id>`: reviewed operation-to-definition projections,
   services, callbacks, lifecycles, object selectors, and honest blockers.
3. `sourcePackages.<id>`: exact authored source bytes plus one C symbol per
   operation.
4. `v6SemanticSlices.<id>`: the independently cached, content-addressed subset
   of `linked-semantic-module-v2` needed to refine the component.
5. `v6WorkPackages.<id>`: a non-authorizing operator package containing the
   interface, semantic slice, immutable faithful-C context, skeleton, required
   dependencies, suggested veto tests, and current blockers.
6. A direct `portable-c-work-package-provider-v2` qualification compiles the
   source for host and PE32, checks the exact ABI and source profile, runs the
   contextual CBMC/refinement, relation, induction, lifecycle, service, and
   ownership kernels that apply, and publishes native objects only when all
   required authority closes.
7. Component-operation service edges are expanded directly from binding intent;
   every selected dependency must itself have a qualified direct provider.
8. `semanticImplementationSelections.<configuration>` is the sole total
   definition-ownership decision. It selects portable objects or immutable
   generated Behavioral C with no implicit per-component fallback.
9. Native realization links selected objects beside generated Behavioral C
   through the one shared runtime and dispatch registry.
   The runtime validates that registry structurally but does not duplicate the
   later provider-selection decision; the payload-bound dispatch/link receipt
   owns exact provider, object, symbol, and RVA authority.

Callback authority is a semantic link fact, not a native-ingress input to a
component. `linked-semantic-module-v2` materializes each reachable callback as
a content-bound code capability with its original target RVA, protocol,
lifetime, target symbol, and root provenance. Component refinement validates
its logical handle against that registry and emits only the semantic target
RVA. At execution, the shared runtime resolves that RVA through the one native
code registry. Bridge symbols and candidate addresses therefore remain native
realization details and cannot enter a component contract or source package.

### One Semantic Boundary

Authored components, adopted libraries, generated Behavioral C, runtime
providers, and the external environment all qualify definitions in the same
semantic-module namespace. A consumer binds the provider operation and semantic
slice identity, never a native object address. Changing presentation-only work
package content therefore does not invalidate contextual proof; changing an
operation's checked semantics does.

Library recognition and adoption remain distinct non-authorizing stages. An
adopted behavior pack uses the same direct provider qualifier and publishes the
same V2 qualification/object records as operator-authored source. Configuration
and runtime code do not interpret recognition-specific receipts. External sites
remain explicit checked environment providers because the operating system is
not a hidden component implementation.

`hybrid` permits generated Behavioral-C ownership for unlifted definitions.
`portable` requires zero generated-C ownership in the selected root-reachable
definition closure. Neither mode permits a selected authored component to
silently fall back.

The component DAG emits no standalone runtime. It generates direct machine-state
overlays, copies exact authored source, cross-compiles PE32 objects, marks owned
units in the total activation plan, and forbids silent fallback inside an
enabled component. Native linking combines those selected objects with immutable
generated behavioral C and the module's one shared runtime.

### Portable Component Interface V5

Portable interface V5 defines typed operations, framework-managed instance
state, protocol states, logical resources, effects, injected services, objects,
lifecycles, callbacks, and checked outcomes without exposing a machine ABI or
raw function pointer. It contains no x86 registers, raw
addresses, PE ranges, import IDs, or
external-site identities. Authored source may not define mutable global state.

The stable component ID and generated C interface namespace are separate. For
example, component `directdraw-init` uses interface namespace
`dxball_directdraw_init`. Receipts bind both explicitly instead of requiring an
operator-facing ID to be a C identifier.

The DX-Ball DirectDraw pilot exercises typed COM services and many joined
cutpoints. Its target-owned success-tail effects remain explicit and
nonauthorizing until their connected-definition or faithful-continuation
boundary is proved.

### Source Contract

Every authored source package is V3 and maps each V5 operation ID to one C
symbol. Single-entry source packages and adapter-specific ABIs are rejected.
Borrowed references, interior pointers, services, callbacks, effects, and
outcomes are expressed by the V5 interface and its checked machine binding,
then imported through the shared runtime boundary transducer.

## Static Refinement Loop

`boundary adopt TARGET component-seed:RVA --input REVIEW --output NEW_DIR`
exports reviewed interface/binding edits for both new and already configured
seeds. A configured seed must retain its component identity. The command checks
the current proposal and exact membership, rejects stale reviews and nonempty
outputs, and preserves draft status and blockers. Installing the exported inputs
into the target remains a separate edit; existing source files are preserved.

One logical effect may reference multiple machine facts, including distinct
writes on loop and terminal paths. Effect references are uniquely identified
and ordered by `(effect_id, unit_id, family, index)`. Repeating the same fact
identity, even with a different digest, is rejected. These references remain
reviewed inputs; behavioral proof and provider qualification are still required.

A review directory may also contain editable `bisimulation.json` in the canonical
component-bisimulation-intent format. Adoption refreshes its self-digest, checks
the component and operation identities and keeps every cut inside the selected
region. It exports `bisimulation/COMPONENT.json` and its lifting-intent reference
in the same transaction as the interface and binding. Invalid formats, extra
fields and symbolic links reject the export. This checks the proposed input's
structure; source markers, invariants and equivalence still need the proof engine.
No binding blocker is removed and no proof receipt is imported by adoption.

If `component check TARGET ID` has no qualification product, it reads the
available canonical binding intent and reports its declared blockers and artifact
path. The suggested development-status command preserves the target flake and
local-build selection. A stale or foreign binding is rejected before displaying
its blockers; an empty blocker list never grants qualification.

When a mutable callee lacks the machine-state premise required at a call,
`component check` follows the qualification-bound proof dependency to the
supplier's wider-entry and cut/exit frame results. It names the operation and
segment, distinguishes a violated premise from an absent one, and prints the
recorded supplier proof identity. This navigation does not turn a local result
into activation authority. Failure of a stronger composition premise alone
does not disprove the supplier's ordinary equivalence; the operator may need
a different boundary or a more general checked state relation.

For mutable leaf operations, the bisimulation intent can propose
`"machine_clobbers": ["ecx", "edx", "esi"]` alongside its existing syncs.
This is an ordered list of machine fields for supplementary proof queries,
not a change to the Portable-C interface. The checker must prove preservation
of every other field at cuts and exits; declared results remain related to
the source result. Every consumed segment needs positive evidence. At a call,
the original side may produce any values in those fields, so a caller that
depends on an unmodeled value will fail its own proof. Declaring a field dead
does not prove it dead. Stack-pointer, private-memory and object-lifetime
changes require their own checked rules.

The same intent can propose `"private_stack_writes": [{"offset": -8, "bytes": 1}]`
for residual original stack writes, separately from logical view permissions.
Offsets are relative to operation-entry ESP; the initial range is limited to
`[-1024, 4096)`. The checker must establish write confinement, a stable ESP at
cuts and the corresponding wider-entry theorem before any caller can consume
the footprint. The original caller then receives arbitrary bytes in those
ranges and must prove that they are harmless to its own behavior. The source
caller does not receive matching arbitrary writes. A changing stack anchor or
an observed residual byte needs further reasoning; the declaration grants no
waiver. Public diagnostics navigate the declared private and clobber premises
instead of requiring the older identity frames for those operations.

Use borrowed memory views when an operation must observe updates made through an
alias during its execution. Scalar state imported at entry is a snapshot; it
cannot represent a word that must be read after overlapping writes. View bases
may use a checked 32-bit register plus signed displacement, with the same modular
address calculation in production and proof. Caller ownership, extent, liveness
and equivalence obligations still require qualification.

Portable source may be authored and compiled from only its reviewed interface.
This development derivation is intentionally small and nonauthorizing: it does
not depend on proposal discovery, resolved machine membership, rooted authority,
or another component's intent.

Activation adds an exact machine binding. The toolkit builds a forced-cutpoint
graph with an entry obligation and authored acyclic or cyclic sync obligations.
Every exact cycle must be cut. Additional acyclic syncs use the same checked
relation and barrier mechanism. Each shard relates arbitrary admitted interface inputs and typed
service responses to the corresponding exact Behavioral-C segment; it does not
enumerate complete paths. One compiled GOTO model is shared by formula-sliced
authored assertions, inventoried paired language-safety partitions, and
nonvacuity witnesses. A concrete mismatch is `violated` with its stable cutpoint and
property location. Missing semantics, timeout, an unwitnessed relation, or
unrepresentable state is `incomplete`. Operator-authored examples and expected
outputs cannot enter this authority path.

A `finite_control_target` result may replace a recovered indirect jump only
when its selector expression, closed target inventory, table bytes, and target
addresses are already machine-derived and checked. The binding assigns portable
logical route values to that exact target set. Materialization expands every
checked selector value into a route, static refinement assumes only the proven
entry domain, and runtime lowering rejects values outside that domain before it
maps the logical route back to the exact machine continuation. A stale table,
selector expression, inventory digest, or non-bijective route map fails closed.

## Contextual Bisimulation

New and migrated Portable-C operations use the universal contextual cutpoint
system described in
[`portable-c-contextual-bisimulation.md`](portable-c-contextual-bisimulation.md).
It proves ordinary connected C directly against an exact Behavioral-C slice,
uses forced entry and checked acyclic or cyclic sync labels as proof barriers, and
materializes no complete paths. The legacy finite-domain and
`init`/`step`/`finish` mechanisms do not
authorize a provider once that operation has migrated.

## Legacy Evidence

This section describes the migration path for older logical C adapters.
`structural-draft-v1` organizes work but never authorizes replacement.

`bounded-equivalence-v1` uses a declared finite input domain. The current
`exhaustive-finite-domain-v1` producer compiles the portable C and compares it
against concrete evaluation of the exact machine IR for every case. It never
executes the original binary. A concrete mismatch is `violated` and includes
the source-level arguments, expected value, and observed value. Unsupported
semantics, an excessive domain, compiler failure, timeout, subprocess crash, or
malformed evidence protocol is `incomplete`. Object-view cases compare the
logical result and the complete reviewed register, flag, memory-write, and
control completion. The C evaluator runs in an isolated subprocess, so a bad
replacement is a localized evidence failure rather than a crashed build
orchestrator. Finite-domain evidence proves only the declared bounded domain;
it is not a universal function theorem.

## Configuration Safety

- Enabled components with exact checked activation authority use portable source.
- Draft, missing, or incomplete components retain generated Behavioral-C
  ownership.
- Every unselected semantic definition retains generated Behavioral-C
  ownership.
- Overlapping ownership is rejected.
- Enabled component members may not fall back individually.
- Whole-program candidate generation requires structural executability; release
  acceptance additionally requires ISA qualification and the activation-bound
  universal component/dependency gate. Candidate-only tests are optional veto
  diagnostics.

Reviewed interfaces may avoid copying long synthesized effect inventories by
using `adapter_effects.inherit_synthesized_except`. Each exclusion names one
exact family, machine-unit ID, and effect index that is represented elsewhere
by a logical result or explicit completion. Missing, duplicate, or stale
references fail contract construction, and the final interface checker still
requires every synthesized effect to have exactly one owner.

## Public Interface

Targets normally use `sdk.workflow.pe32`, then inspect
`workflow.components`. Low-level construction remains available as
`sdk.lifting.components` for tooling tests.

```nix
environment = sdk.environment.pe32 {
  id = "program-win32";
  profilePacks = [ runtimeProfile ];
  interfacePacks = [ ];
  launchProfile = launchProfile;
  boundaryIntents = { };
  support.processTermination = null;
};

workflow = sdk.workflow.pe32 {
  original = originalExe;
  targetId = "program";
  binaryIdentity = "program.exe";
  externalEnvironment = environment;
  lifting = {
    boundaries = [ ];
    components = {
      intent = ./intent/components.json;
      operatorRoot = ./intent;
      sourceRoot = ./source;
    };
    libraries = { packs = [ ]; adoptionRoot = ./intent/libraries; };
  };
  backend = { kind = "behavioral-c"; sourcePresentation = null; };
  analysisLimits = { maxUnits = 512; maxCandidatesPerSeed = 12; };
};

workPackage =
  workflow.components.v6WorkPackages."ascii-to-lower";
selection =
  workflow.semanticImplementationSelections."one-enabled-component";
candidate = workflow.nativeRealizations."one-enabled-component";
```

For an authored portable unit, `component build` realizes the independent
compile receipt. `component status --development` reports the local
contract/source/evidence progress without pulling realization authority.
`component status` reports the strongest available checked implementation and
dependency state, and `component check` requires those machine-derived facts.
Draft units remain independently compilable; configurations remain authority
gated.

`component check --source --local-contracts` reports a detected local proof
counterexample as `violated`; a timeout or unsupported model remains
`incomplete`. A counterexample remains visible even if another local obligation
times out. Diagnostics identify the operation and proof kind. Local success
still grants no provider or connected-summary authority. For selected shared
services, text output names the contract and its identity; JSON also includes
its ABI and effect-contract digests under `local_contract.service_dependencies`.
These identify the selected premises, rather than establish compatibility or
independent runtime validation. The existing fixed-view shared-service model
does not yet admit allocation/release lifetimes or arbitrary dynamic views.

A manually configured `sourceCheck` can prepare an authored service-call boundary
using `sourceCallRegions = ./source-call-regions.json` in
`nix/component-source-check.nix`. The file is an array of the existing manual
source anchor records:

```json
[{
  "operation_id": "cleanup",
  "source": "cleanup.c",
  "entry": {"position": "before", "text": "      spx_view_v5 message = context->services->resource_text(context->services->context, 31U);\n"},
  "exits": {
    "next": {"position": "after", "text": "      spx_view_v5 message = context->services->resource_text(context->services->context, 31U);\n"}
  }
}]
```

`component check TARGET COMPONENT --source --json` exposes `source_call_regions`.
Each prepared projection binds the complete source/interface, inert marker
correspondence, compiled cut instructions, actual service arguments, context type
and live result local. Models, include inventories and compiler outputs are
retained in `source-call-region-models/`. Unsupported effects/control or stale
anchors produce `incomplete`. The current projection admits one unconditional
view-returning service call with uint32 constant arguments; general regions and
live-state transport require the wider cut engine.

For a graph of manual proof regions, the same constructor accepts
`sourceRegionGraphs = ./source-region-graphs.json`. Each array element uses the
same `operation_id`, `source`, `entry` and `exits` anchors, plus `regions`: a
nonempty list selecting which declared cuts start regions. The primary anchor
is named `entry`; the other cut names come from `exits`. Every selected region
is followed to the next declared cut or C return. Back edges between regions
are supported; an internal cycle produces a diagnostic requesting another cut.
For example, cuts around a cleanup loop, its copy branch, its cursor advance and
its tail can select `regions = [ "entry", "copy", "advance" ]`, leaving the tail
explicitly unselected.

`component check TARGET COMPONENT --source --json` exposes `source_region_graphs`.
Each graph reports edges, direct or computed call dependencies, referenced
storage, incoming edges into region interiors, uncovered scope and semantic
digests for individual regions. Compiler labels and constant routing immediately
before a cut belong to that cut, so joins do not invent overlapping ownership.
The digests retain typed operands and control flow while excluding absolute
instruction positions. A changed region can therefore preserve neighboring
region bindings. This does not itself reuse a correctness proof or establish
contract compatibility. Complete compiler inputs and inventories are retained
in `source-region-graph-models/`, and the feedback reader reconstructs the graph
from them without compiling or solving.

Graph preparation does not prove liveness, boundary-state transport, memory
contracts, progress or original/source equivalence. Calls remain unqualified
dependencies. Selected proof regions are not automatically authoring components
or replacement groups, and partial coverage cannot authorize activation.

A `sourceContractCheck` product can consume a prepared graph with
`nix/component-source-region-check.nix`. Supply `sourcePreparation`, `exactSlice`,
`contract`, and optionally `previous`; invoke it through
`component check TARGET COMPONENT --source --local-contracts --json`.
The entry contract `local-text-cleanup-entry-v1` is illustrated by
`tests/fixtures/metapad-cleanup-entry/local-contract.json`. It requires the real
function entry, checked length/allocation/byte-access expressions and a closed
prefix up to the loop cut. The comparison executes the actual short-input path,
checks allocation arguments and faults, and captures the complete scratch view,
cursor/count state, saved machine frame and eight refined loop-memory predicates.
Concrete length/allocation implementations and incoming lifetimes remain explicit
runtime premises. Other services or public context accesses report incomplete.

The iteration contract is `local-byte-compaction-step-v1`, illustrated by
`tests/fixtures/metapad-cleanup-iteration/local-contract.json`. It names selected
regions, entry/exit cuts and original RVAs, ordinary local cursor/count/view roles,
machine registers, private cells and clobbers. This is a conditional iteration
profile, not a general arbitrary-region theorem interface. Only byte-view access
calls are supported within the selected step. Early C returns must be the
UINT32_MAX fault outcome; other return values need a separate outcome contract
and are rejected before proof compilation. Other services need their own
checked composition contracts.

The same product accepts the terminal `local-text-cleanup-tail-v1` profile in
`tests/fixtures/metapad-cleanup-tail/contract.json`. Its manually selected cuts
must cover the complete terminal closure, including ordinary returns. Supply the
checked resource supplier separately:

```nix
sourcePreparation = sourceCheck.derivation;
exactSlice = retainedCleanupTail;
contract = ./cleanup-tail-contract.json;
dependencies.resource_text = resourceText.sourceContractCheck;
previous = previousCleanupTailCheck; # Omit for the first check.
solver = "cadical";
timeoutSeconds = 300;
```

The tail profile admits the supported byte accesses and copy, release,
resource-text, message and focus interactions. It checks the exact original call
edge, complete supplier reference and private frame, and compiled source effects.
Other service shapes, pointer aliases and unmodeled context reads report
incomplete. This profile still encodes a specific stack/view convention; it is
not a general boundary language for arbitrary services or heaps.

The consumer model omits both resource-supplier bodies. Its proof key binds the
complete checked supplier domain, while the output separately binds the current
implementation receipt. A requalified implementation with an equal domain can
reuse the consumer theorem; changing admission or dependency contracts requires
rechecking or reports an unsupported composition. Feedback exposes dependencies
under `local_contract.region_comparison.dependencies`. Host C callback type
checking precedes GOTO compilation, and its exact inputs are retained with the
proof. Conditional success does not qualify concrete runtime services or compose
the cleanup entry, loop and tail into a complete component.

`tests/fixtures/metapad-authored-call/cleanup-regions.json` defines one shared
manual graph for the complete ordinary cleanup operation. Place this object in
the array supplied as `sourceRegionGraphs`, then use that same preparation for
the entry, loop and tail products. The entry selects `entry` and `prefix_iter`
and exits at `loop`; the loop selects `loop`, `copy` and `advance` and exits at
`tail`; the tail selects `tail` and `tail_iteration`. Match these names in each
contract and select loop runtime revision 3. Proof markers and entry/exit observers
remain confined to comparison copies of the source.

Graph feedback reports `uncovered_reachable_instruction_count` separately from
`uncovered_instruction_count`. The latter also includes compiler records after
returns. Zero uncovered reachable instructions establishes structural coverage
under the graph's C-return convention; it does not establish lifetime, progress,
state compatibility or functional correctness. Even successful local proofs on
the same complete graph require checked composition before they establish the
complete component theorem.

For the supported cleanup profiles, `nix/component-source-composition-check.nix`
consumes `regions = { entry = ...; loop = ...; tail = ...; }` and optional
`previous`. Expose its derivation as the component's `sourceContractCheck` to use
`component check --source --local-contracts`. This phase imports complete current
regional evidence and extracts spatial assumptions from the actual proved models;
its own model contains no application or neighboring bodies. It compares existing
entry admission with the loop/tail requirements, then checks an explicit proposed
caller/allocator envelope and a nonempty-domain witness. `previous` can reuse these
queries after current regional receipts are revalidated and rebound.

The composition phase also checks private-byte transport. It lowers the actual
proved private read/write clauses to cell-layout tables, then uses a fixed recipe
to establish correspondence with one arbitrary byte-backed private object.
Individual stores preserve the relation and all other bytes; entry/loop/tail
transport preserves saved registers, the return word, count and partial-word
temporaries. The checker imports the fixed recipe and parses its retained tables
without regenerating the model. This is conditional representation transport,
not physical memory accessibility or object lifetime qualification.

Current public-memory transport is checked separately. The composition rule
instantiates the successor's incoming byte function with the predecessor's
current contents at every physical address. Both sides use that same function;
discarding write history does not discard its resulting bytes. At the tail cut,
the zero-suffix representation must equal those contents under the predecessor's
checked zero-suffix guarantee. The query checks arbitrary bytes, physical aliases
and all eight public-memory predicates. Exact regional guarantees, consumer
premises and the tail's byte reader are bound into the reusable proof key. This
rule neither reconstructs objects from pointers nor establishes their lifetime.

Live descriptor transport checks the six actual view accessors and the tail's
write guard against separate live opaque contexts. Public reference fields remain
exact. The complete owned source graph is also checked for scratch-grant issuance,
use and revocation, with all seven source regions covered. Normal returns require
revocation; fault returns retain their actual grant state. Neither check proves
physical allocation lifetime or deallocation success. Feedback includes four
named versioned runtime requirements for persistent borrow storage, hook frames,
non-retaining services and release outcomes, each explicitly unverified.

Feedback is under `local_contract.region_composition`. Additional requirements
distinguish caller stack/text/image separation from future allocator placement.
Selecting the proposed envelope does not establish these requirements for any
actual caller. The public result therefore remains `incomplete` (CLI exit 2), even
when its spatial, private-byte, current-memory and descriptor implications succeed. Physical
private-frame compatibility, descriptor lifetime, concrete services and complete operation composition remain
separate obligations. No extra production function or component boundary is added.

The comparison executes the actual ordinary C and exact original region under
an explicit current-memory relation, checks exit state and preserved registers,
whole public memory, and progress/invariant preservation on a repeated cut.
Compiled transport checks every selected source instruction and its automatic
state restoration; private observer code can assert but cannot mutate source
state. Partial source cuts are merged for the local comparison by erasing only
checked inert markers. Authoring components and production APIs stay unchanged.

`local_contract.region_comparison` reports the selected scope, named runtime
premises and proof reuse. The key binds selected typed region semantics, interface,
original bytes, contract, headers, tools and engine code. An outside-source edit
must undergo fresh source preparation; if selected semantics remain unchanged,
evidence import rechecks current compiled transport against the retained local
model without model generation, compilation or solving. This establishes reuse
of a proof region inside a component; it does not count that region as another
independently lifted authoring component. A successful comparison still reports
`whole_component_complete = false`, `runtime_compatibility = "unverified"` and
`activation_authorized = false`. Entry admission, remaining coverage, allocation
and lifetime premises, and runtime qualification require separate evidence.

**Preparation is not a functional proof.** A changed ID may prepare successfully
and still fail the separate original/source comparison. Feedback explicitly
reports `functional_correctness_checked = false` and no activation authority.
A `sourceContractCheck` product can consume that preparation using
`nix/component-source-call-check.nix`:

```nix
{
  sourcePreparation = sourceCheck.derivation;
  exactSlice = originalCallerSlice;
  supplier = checkedOriginalSupplier;
  contract = ./caller-contract.json;
  previous = previousCallerCheck; # null for a fresh comparison
}
```

The contract selects the prepared region, original entry/call/return RVAs,
service identity, private-stack span and live word inventory, and the returned
reference representation. See `tests/fixtures/metapad-call-comparison/contract.json`
for the retained Metapad example. Admission derives readable/writable image views,
clobbers and child stack requirements from the checked supplier, rejecting a
supplier whose private frame exceeds the caller's admitted storage. It does not
silently narrow the caller's original inputs to accommodate a new supplier.

`component check TARGET COMPONENT --source --local-contracts --json` reports
`local_contract.caller_comparison`, including region status, reuse counts,
supplier domain/receipt identities and the named runtime assumptions. A compatible
supplier implementation edit retains the exact caller proof without generating,
compiling or solving the consumer again. A changed contract requires rechecking;
an incompatible caller domain rejects before those steps. Preparation remains an
independent product shared by these cases. The current checker supports one
constant-argument, borrowed-image call region, with a checked normal cdecl
supplier. Successful regional proof leaves `whole_component_complete = false`,
`runtime_compatibility = "unverified"` and `activation_authorized = false`.
Surrounding reachability, coverage/progress, runtime compatibility and replacement
qualification require separate evidence.

A manually configured `sourceContractCheck` product can additionally compare a
complete fixed-image shared-service leaf with its original Behavioral-C. The
existing `nix/component-source-check.nix` constructor accepts:

```nix
originalComparison = {
  exactSlice = exactCPackage;
  bindingIntent = ./binding.json;
  machineDomain = ./machine-domain.json;
};
```

This requires `localContracts = true`, an explicit `sharedContract` with selected
service bindings, and no component dependencies yet. The domain file declares
the image base/size, admitted private stack accesses/writes and register clobbers.
The checker validates source profile and compiled opacity evidence, links the
same authored GOTO object into the paired model, and checks the exact original
files and compiler inputs. It does not recompile authored C under different proof
headers. The existing public command remains
`component check TARGET COMPONENT --source --local-contracts`.

JSON feedback includes `local_contract.original_comparison`; detailed models,
input bindings and raw query evidence live under `original-comparison/` in the
product. Functional differences are `violated`; stale or unsupported inputs and
timeouts are `incomplete`. A passing comparison is conditional on its named
borrowed-image runtime contract and reports runtime compatibility as unverified.
Successful feedback also exposes `transition_domain_sha256`, after independently
reading the retained source/original evidence. This identifies the consumed
behavior/interface/runtime domain separately from the implementation receipt.
A changed signature is not its only invalidation trigger: private frames,
service assumptions and original behavior identity also matter. This domain is
an input to conditional caller experiments; public source-bound caller composition
is not implemented yet.
It cannot authorize a provider, qualified connected summary or activation. The ordinary
resource-text service profile proves alias/effect equivalence without a NUL
output premise; a caller requiring a string must discharge that invariant
separately. This is currently a leaf capability, not transitive composition.

An internal experimental world lowering implements the named
`issued-reference-access` runtime contract, revision 2. It derives the origin
capacity and native allocation-class guards from checked inputs, requires
interior-pointer support in every authority rule, and checks issued metadata,
current lifetime, permissions, offset arithmetic and null policy on access.
It omits native re-realization while retaining resolution, origin issuance,
memory and allocation transitions. Its generated C requires a contract-digest
compilation marker supplied by explicitly conditional obligation execution.
The existing evidence cache binds that selection; strong readers reject the
result and any extracted conditional frame certificate.

The independently selectable `allocation-byte-projection:2` generator takes one
allocation snapshot per byte lookup and preserves the original ordering of
private writes, public writes and shadow bytes. It retains separate history
floors, imported current contents, fresh initialization and call/summary oracle
identities. With this selection alone, the existing native reference resolver
remains active. With both selections, each generated lowering requires its own
contract-digest compilation marker. Generation rejects unknown or mismatched
contracts even though the generic evidence cache can retain externally authored
conditional identities.

The independently selectable `world-reference-summary:2` generator implements
checked PE32 image/allocation namespace lookup and context validation. Its native
comparison checks cover bounded layouts, status, aliases, extent, permissions,
lifetime, failure outputs and unchanged world contents. These checks do not
establish universal platform correctness. Revision-1 regional evidence does not
prove the combined revision-2 model.

For a configured `conditionalCheck` product, `component check TARGET ID
--conditional [--json]` runs contextual checking under the exact selected runtime
contracts. It reports `complete`, `incomplete` or `violated`, names the contract
revisions and digests, and explicitly grants no activation authority. The option
is exclusive with `--source` and `--local-contracts`. Targets without a configured
product report that absence instead of silently changing proof modes.

Configure the existing `sdk.candidate.portableCWorkPackageProviderV2` builder
with its ordinary component inputs plus `runtimeAssurance` (an implemented
selection) and `conditionalTargetId`. Publish its `derivation` as the unit's
`conditionalCheck` product in the operator target and index. The builder exposes
`conditionalEngineResult` and `engineDerivation` for inspection. The proof phase
retains exact inputs and assurance; a separate operator phase renders feedback.
Changing presentation therefore does not require rebuilding the proof phase.
The conditional exit emits no provider qualification, object manifest or
replacement choices. It does not perform native linking or discharge all
portability obligations. Existing supplier admission still applies during
preparation; conditional checking does not admit stale neighboring receipts.
Unchanged whole-engine outputs can be reused by Nix. To reuse completed queries
while checking again, pass the earlier `engineDerivation` directory through
`previousQueryEvidence`; the feedback derivation does not carry query outputs.
Conditional packets remain separate from ordinary contextual-refinement receipts.
The importer checks the packet, model/obligation correspondence and exact runtime
selection. Each query hit additionally requires identical compiled bytes, tools,
arguments and retained output, reparsed by the current checker. Changed contracts
invalidate reuse; missing queries run again and cached counterexamples remain
counterexamples. An ordinary proof cannot import a conditional packet.
The current source include path is part of compiled-model identity, so moving an
otherwise identical source package may invalidate reuse. Reusing a query is not
admitting its packet as a checked supplier summary; that composition remains
unimplemented. Presentation reuse must not be reported as neighboring-proof reuse.
JSON feedback exposes auxiliary checks under `details.composition_facts`; text
feedback lists the unavailable ones. `complete` means the ordinary contextual
obligations passed under the named runtime contracts. It does not imply that
every optional wider-entry or frame candidate passed. Each caller must still
establish the facts required by its selected composition rule. An unresolved
auxiliary query may rerun after an exact repair even when all ordinary queries
reuse, so inspect these results when diagnosing edit latency.
The fixed-view source check and whole-component qualification retain their
existing meanings.

For a configured unit that has no source yet, `component start` is the only
public source transition. `--output DIR` hash-checks the V6 package, its semantic
slice, generated files, and faithful-C excerpts before copying the whole package
into a writable directory. `--apply` is deliberately narrower: it accepts only
a writable local target, requires `target.json` to declare
`paths.component_sources`, refuses existing source, rewrites the package-local
header include to the canonical V5 implementation header, and updates the
existing `component-lifting-intent-v1` source row and digest. A process lock,
same-filesystem staging, preflight checks, and rollback make the two-file
application an atomic command-level transaction. Component seeds remain
non-authorizing proposals until an operator authors their canonical interface,
binding, and lifting-intent row; the retired component-adoption receipt is not
produced.

Each indexed candidate configuration fixes its mode. Hybrid configurations
allow checked fallback; portable configurations require wholly portable
ownership throughout the checked root-reachable projection. `candidate build`
consumes that configuration's checked selection and the target's static release
gate. There is no separate public candidate-check product or mode override;
diagnostic dependency reports cannot make a candidate executable.

`candidate status` keeps those two questions separate. `exact-selection`
reports whether every required definition and obligation has one checked
provider. The accompanying definition/obligation coverage counts selected
`qualified_portable_c`, `generated_behavioral_c`, `qualified_runtime`,
`external_environment`, and `pinned_binary` providers and reports portable
progress independently. Thus an exact Behavioral-C-backed selection is complete
without being mislabeled as decompilation progress.

Pure component qualification depends only on its selected machine-IR units and
checked component artifacts. A component that declares an external-site service
also depends on the canonical target/ABI evidence for that site. Neither path
depends on root-scoped target ISA qualification or final candidate acceptance; those
remain release-level gates.

`runtime` above is exactly the runtime package consumed by the default-compiler
candidate. Building it does not pull an executable candidate into its closure.
`workflow.components.v6SemanticSlices`,
`workflow.components.v6WorkPackages`,
`workflow.semanticImplementationSelections`, and
`workflow.nativeRealizations` provide the corresponding
configuration-indexed families. The operator-facing interface
also exposes independently cached work packages, status reports, and checks for
every leaf or group, plus runtime/status/check products for each configuration.

Adding a target should not require generic Python or Nix changes. A reusable
capability gap must be implemented in the toolkit and covered by a small
target-independent fixture before a validation target relies on it.

## Library Islands

`library status` and `library inspect` discover ABI-compatible whole-library
islands. `library adopt --island ... --recipe ...` writes a content-bound V1
adoption intent for an available reusable behavior pack; `--draft` records an
operator recipe that still needs static qualification. Discovery, adoption,
checked-island authority, and generated component construction are separate
content-addressed phases.

An adopted island becomes executable only when the canonical checker closes
identity, every crossing boundary, and the selected implementation, then emits
a complete generated ordinary component. The component runtime consumes that
package through the same ownership, adapter, semantic-contract, and compilation
path as an operator-authored component. Unselected or incomplete islands do not
block the target and retain machine-IR fallback ownership.

Automatic generated-component materialization currently covers stateless,
nonvariadic scalar ABIs with register or stack arguments and scalar results.
Stateful services, variadic calls, hidden return storage, out-parameters, and
externally visible effects fail closed until the behavior pack supplies an
explicit checked machine-to-portable mapping template.
